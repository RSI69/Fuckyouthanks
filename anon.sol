// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";


contract ANONToken is ERC20, ReentrancyGuard {
    using ECDSA for bytes32;

    struct Withdrawal {
        uint256 amount;
        uint256 unlockTime;
        address recipient;
        uint8 retryCount;
        uint256 lastAttempt;
    }

    mapping(address => mapping(uint256 => bool)) private usedEntropy;
    mapping(bytes32 => bool) private queued;    
    mapping(address => uint256) public userLastMint;
    mapping(uint256 => uint256) private gasPoolForBatch;
    mapping(uint256 => bytes32) private withdrawalQueue;
    mapping(bytes32 => Withdrawal) private pendingWithdrawals;
    mapping(bytes32 => bool) private processedWithdrawals;
    mapping(bytes32 => bool) public usedSignatures;
    mapping(address => uint256) public burnIds;
    mapping(uint256 => address) public batchCaller;

    uint256 public lastProcessedTime;
    uint256 private totalProcessedWithdrawals;
    uint256 private withdrawalStart;
    uint256 private withdrawalEnd;
    uint256 private constant GAS_HISTORY = 5;
    uint256[GAS_HISTORY] private gasPriceHistory;
    uint256 private gasIndex = 0;
    uint256 private constant DEFAULT_TIP = 100 wei; 

    bytes32[] private activeWithdrawalKeys;

    uint256 public immutable mintPrice = 0.00000001 ether;
    uint256 public constant MIN_DELAY = 1 minutes;
    uint256 public constant MAX_DELAY = 720 minutes;
    uint256 public constant BASE_PROCESS_TIME = 60 minutes;
    uint256 public constant RETRY_INTERVAL = 24 hours;
    uint8 public constant MAX_RETRY_ATTEMPTS = 7;

    uint256 public immutable feeBasisPoints = 0; // 0.3%
    address constant FEE_RECIPIENT = 0x0000000000000000000000000000000000000000;

    uint256 public constant MIN_ANONYMITY_SET = 50;

    event Minted(address indexed user, uint256 amount);

    event WithdrawalFailed(bytes32 commitmentHash, address recipient, uint256 refundAmount, uint8 retryCount);
    event WithdrawalSentToFeeRecipient(bytes32 commitmentHash, uint256 amount);

    constructor() ERC20("ANON Token", "ANON") {
        lastProcessedTime = block.timestamp;
        uint256 seed = (block.basefee == 0)          
            ? tx.gasprice
            : block.basefee + DEFAULT_TIP;          
        for (uint256 i = 0; i < GAS_HISTORY; i++) {
            gasPriceHistory[i] = seed;
        }
    }

    function calculateFee(uint256 amount) public pure returns (uint256) {
        return (amount * feeBasisPoints) / 10000;
    }

    function mint() external payable nonReentrant {
        require(msg.value == mintPrice, "Incorrect ETH amount sent");
        require(block.timestamp > userLastMint[msg.sender] + 10, "Too soon after last mint");
        userLastMint[msg.sender] = block.timestamp;
        _mint(msg.sender, 1 ether);
        emit Minted(msg.sender, 1 ether);
        lastProcessedTime = block.timestamp;        
    }

    function requestBurn(address stealthRecipient, bytes memory signature, uint256 userEntropy) external payable nonReentrant {
        require(balanceOf(msg.sender) >= 1 ether, "Insufficient ANON balance");
        require(msg.value >= 1e15, "Must send enough ETH to cover gas and fee.");
        updateGasHistory();   
        uint256 requiredGas = estimateGasCost();           
        uint256 deliverable = msg.value - requiredGas;
        uint256 fee = calculateFee(deliverable);
        uint256 netValue = deliverable - fee;
        require(msg.value >= requiredGas + fee, "Insufficient value");
        require(userEntropy != 0, "Entropy required");
        (bool feeSent, ) = payable(FEE_RECIPIENT).call{value: fee}("");
        require(feeSent, "Fee transfer failed");
    
        require(netValue >= estimateGasCost(), "Did not fund gas pool");
        
        uint256 burnId = burnIds[msg.sender];         // id belongs to the caller

        bytes32 signedHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                _msgHash(stealthRecipient, burnId, msg.sender, msg.value, userEntropy)
            )
        );

        address signer = ECDSA.recover(signedHash, signature);
        require(signer == msg.sender, "Signature/owner mismatch");  // prevents front‑running

        bytes32 commitmentHash =
            _commitHash(stealthRecipient, burnId, netValue, userEntropy);

        require(!usedSignatures[signedHash], "Signature already used");
        require(!usedEntropy[msg.sender][userEntropy], "Entropy reused");
        usedEntropy[msg.sender][userEntropy] = true;
        usedSignatures[signedHash] = true;

        uint256 randomDelay = secureRandomDelay(commitmentHash);

        require(withdrawalEnd - withdrawalStart < 30_000, "Queue limit exceeded");

        // require(msg.sender == tx.origin, "Contracts not allowed");

        pendingWithdrawals[commitmentHash] = Withdrawal({ 
            amount: netValue,
            unlockTime: block.timestamp + randomDelay,
            recipient: stealthRecipient,
            retryCount: 0,
            lastAttempt: 0
        });

        require(!queued[commitmentHash], "Commitment already queued"); // O(1) dedup
        queued[commitmentHash] = true;

        withdrawalQueue[withdrawalEnd] = commitmentHash;
        withdrawalEnd++;
        uint256 batchId = (withdrawalEnd - 1) / MIN_ANONYMITY_SET;
        gasPoolForBatch[batchId] += netValue;
        activeWithdrawalKeys.push(commitmentHash);

        burnIds[signer]++;
        _burn(signer, 1 ether);

        if ((withdrawalEnd - withdrawalStart) % MIN_ANONYMITY_SET == 0) {
            if (batchCaller[batchId] == address(0)) {
                batchCaller[batchId] = msg.sender;
            }
        }


        if ((withdrawalEnd - withdrawalStart) >= MIN_ANONYMITY_SET) {
            _processWithdrawalsInternal();

        }
    }

    function _processWithdrawalsInternal() private {
        require((withdrawalEnd - withdrawalStart) == MIN_ANONYMITY_SET, "Must process exactly 50");
        require(msg.sender == tx.origin, "No contracts");

        uint256 batchId = withdrawalStart / MIN_ANONYMITY_SET;
        require(msg.sender == batchCaller[batchId], "Only last burner can process this batch");
        delete batchCaller[batchId];                       // cleanup
        require(burnIds[msg.sender] > 0, "Must be recent burner");

        uint256 gasStart = gasleft();

        /* ---------- gas pool ---------- */
        uint256 availablePool = gasPoolForBatch[batchId]; 

        require(
            availablePool >= estimateGasCost() * MIN_ANONYMITY_SET,
            "Gas pool under funded"
        );

        /* ---------- shuffle commitments ---------- */
        bytes32[] memory shuffled   = new bytes32[](MIN_ANONYMITY_SET);
        address[] memory recipients = new address[](MIN_ANONYMITY_SET);

        uint256 completedCount = 0;

        for (uint256 i = 0; i < MIN_ANONYMITY_SET; i++) {
            bytes32 h = withdrawalQueue[withdrawalStart + i];
            shuffled[i]   = h;
            recipients[i] = pendingWithdrawals[h].recipient;
        }
        for (uint256 i = MIN_ANONYMITY_SET - 1; i > 0; i--) {
            uint256 j = uint256(keccak256(abi.encodePacked(block.prevrandao, i))) % (i + 1);
            (shuffled[i], shuffled[j])     = (shuffled[j], shuffled[i]);
            (recipients[i], recipients[j]) = (recipients[j], recipients[i]);
        }

        /* ---------- main withdrawal loop ---------- */
        for (uint256 i = 0; i < MIN_ANONYMITY_SET; i++) {
            bytes32 commitmentHash = shuffled[i];
            Withdrawal storage w   = pendingWithdrawals[commitmentHash];

            if (
                processedWithdrawals[commitmentHash] ||
                block.timestamp < w.unlockTime ||
                block.timestamp < w.lastAttempt + RETRY_INTERVAL
            ) { continue; }

            w.lastAttempt = block.timestamp;

                        /* EFFECTS */
            address recipient = w.recipient;
            uint256 amountWei = w.amount;

            /* INTERACTION */
            (bool ok, ) = payable(recipient).call{value: amountWei}("");

            if (ok) {
                /* SUCCESS: mark processed and clean up */
                processedWithdrawals[commitmentHash] = true;
                delete pendingWithdrawals[commitmentHash];
                queued[commitmentHash] = false;
                completedCount += 1;
            } else {
                /* FAILURE: increment retry counter */
                w.retryCount += 1;

                if (w.retryCount >= MAX_RETRY_ATTEMPTS) {
                    // Give up → send to fee recipient, mark processed
                    (bool feeOk, ) = payable(FEE_RECIPIENT).call{value: amountWei}("");
                    require(feeOk, "FeeRecipient transfer failed");

                    processedWithdrawals[commitmentHash] = true;
                    delete pendingWithdrawals[commitmentHash];
                    queued[commitmentHash] = false;
                    completedCount += 1;
                    emit WithdrawalFailed(
                        commitmentHash,
                        recipient,
                        amountWei,
                        w.retryCount
                    );
                }
            }

        }

        /* ---------- reimburse caller ---------- */
        uint256 gasUsed = gasStart - gasleft();
        uint256 effectivePrice = block.basefee + DEFAULT_TIP;
        uint256 weiUsed = gasUsed * effectivePrice;
        uint256 cap = availablePool / MIN_ANONYMITY_SET;
        uint256 callerPay = weiUsed > cap ? cap : weiUsed;

        (bool success, ) = payable(msg.sender).call{value: callerPay}("");
        require(success, "Gas reimbursement failed");

        /* ---------- update gas pool ---------- */
        availablePool -= callerPay;   // what remains after reimbursing caller

        if (completedCount == MIN_ANONYMITY_SET) {
            _finalizeBatch(batchId, availablePool, recipients);
        } else {
            // keep leftovers for retries
            gasPoolForBatch[batchId] = availablePool;
        }
    }



    function updateGasHistory() internal {
        gasPriceHistory[gasIndex] = tx.gasprice < block.basefee ? block.basefee : tx.gasprice;
        unchecked {
            gasIndex = (gasIndex + 1) % GAS_HISTORY;
        }
    }

    function processWithdrawals() external nonReentrant {
        _processWithdrawalsInternal();
    }

    function estimateGasCost() public view returns (uint256) {
        uint256 weightedSum = 0;
        uint256 totalWeight = 0;

        for (uint256 i = 0; i < GAS_HISTORY; i++) {
            uint256 index = (gasIndex + GAS_HISTORY - 1 - i) % GAS_HISTORY;
            uint256 weight = 2**(i + 1); // newer entries (later in array) have more weight
            weightedSum += gasPriceHistory[index] * weight;
            totalWeight += weight;
        }

        uint256 ewmaGasPrice = weightedSum / totalWeight;
        uint256 paddedGasPrice = ewmaGasPrice + (ewmaGasPrice / 8); // add 12.5% buffer
        uint256 usedGasPrice = tx.gasprice > paddedGasPrice ? tx.gasprice : paddedGasPrice;

        return 375_000 * usedGasPrice;
    }

    function secureRandomDelay(bytes32 seed) internal view returns (uint256) {
        // seed = commitmentHash (contains sender addr, burnId, timestamp, etc.)
        bytes32 h = keccak256(
            abi.encodePacked(
                seed,
                block.prevrandao,          // PoS randomness, unpredictable to user
                block.timestamp,           // miner‑controlled but bounded
                address(this)              // extra salt
            )
        );
        return MIN_DELAY + (uint256(h) % (MAX_DELAY - MIN_DELAY));
    }

    /* ---------- internal helpers to shrink stack ---------- */
    function _msgHash(
        address stealthRecip,
        uint256 burnId,
        address caller,
        uint256 value,
        uint256 entropy
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                stealthRecip,
                burnId,
                caller,
                address(this),
                block.chainid,
                value,
                entropy
            )
        );
    }

    function _commitHash(
        address stealthRecip,
        uint256 burnId,
        uint256 value,
        uint256 entropy
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                stealthRecip,
                burnId,
                block.prevrandao,
                block.timestamp,
                value,
                entropy,
                block.chainid
            )
        );
    }
    function _finalizeBatch(
        uint256 batchId,
        uint256 availablePool,
        address[] memory recipients
    ) private {
        // refund true surplus & clean queue
        uint256 extraPerUser = availablePool / MIN_ANONYMITY_SET;
        uint256 dust         = availablePool - (extraPerUser * MIN_ANONYMITY_SET);

        for (uint256 i = 0; i < MIN_ANONYMITY_SET; i++) {
            (bool refunded, ) = payable(recipients[i]).call{value: extraPerUser}("");
            if (!refunded) {
                (bool feeSent, ) = payable(FEE_RECIPIENT).call{value: extraPerUser, gas: 30_000}("");
                require(feeSent, "Extra fee transfer failed");
            }
            delete withdrawalQueue[withdrawalStart + i];
        }                           // ← closes the for-loop (ONLY ONE brace here)

        delete activeWithdrawalKeys; // prune array

        if (dust > 0) {
            (bool dustSent, ) = payable(FEE_RECIPIENT).call{value: dust, gas: 30_000}("");
            require(dustSent, "Dust transfer failed");
        }

        delete gasPoolForBatch[batchId];
        withdrawalStart += MIN_ANONYMITY_SET;

    }

    function getRandomizedInterval() internal pure returns (uint256) {
        return BASE_PROCESS_TIME;
    }

    
}

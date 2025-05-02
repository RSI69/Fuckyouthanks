// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract ANONToken is ERC20, ReentrancyGuard {
    using ECDSA for bytes32;

    struct Withdrawal {
        uint256 amount;
        uint256 unlockTime;
        address recipient;
        uint8 retryCount;
        uint256 lastAttempt;
    }

    mapping(address => bytes32) public userCommitment;
    mapping(address => uint256) public userLastMint;
    mapping(uint256 => uint256) private gasPoolForBatch;
    mapping(uint256 => bytes32) private withdrawalQueue;
    mapping(bytes32 => Withdrawal) private pendingWithdrawals;
    mapping(bytes32 => bool) private processedWithdrawals;
    mapping(bytes32 => uint256) private activeKeyIndex;
    mapping(bytes32 => bool) public usedSignatures;
    mapping(address => uint256) public burnIds;
    mapping(uint256 => address) public batchCaller;

    bytes32 public merkleRoot;
    uint256 public lastProcessedTime;
    uint256 private totalProcessedWithdrawals;
    uint256 private withdrawalStart;
    uint256 private withdrawalEnd;
    uint256 private constant MERKLE_UPDATE_THRESHOLD = 20;
    uint256 private constant GAS_HISTORY = 5;
    uint256[GAS_HISTORY] private gasPriceHistory;
    uint256 private gasIndex = 0;
    uint256 public commitCount;

    bytes32[] private activeWithdrawalKeys;

    uint256 public immutable mintPrice = 0.00000001 ether;
    uint256 public constant MIN_DELAY = 1 minutes;
    uint256 public constant MAX_DELAY = 720 minutes;
    uint256 public constant BASE_PROCESS_TIME = 60 minutes;
    uint256 public constant RETRY_INTERVAL = 24 hours;
    uint8 public constant MAX_RETRY_ATTEMPTS = 7;

    uint256 public immutable feeBasisPoints = 30; // 0.3%
    address constant FEE_RECIPIENT = 0xDCeCF114cdA49c2bf264181065c46aa786A4d084;

    uint256 public constant MIN_ANONYMITY_SET = 50;

    event Minted(address indexed user, uint256 amount);
    event MerkleRootUpdated(bytes32 newRoot);
    event WithdrawalFailed(bytes32 commitmentHash, address recipient, uint256 refundAmount, uint8 retryCount);
    event WithdrawalSentToFeeRecipient(bytes32 commitmentHash, uint256 amount);
    event CommitReceived(address indexed who, bytes32 commitmentHash);

    constructor() ERC20("ANON Token", "ANON") {
        lastProcessedTime = block.timestamp;
        // Initialize gasPriceHistory[] with the current tx.gasprice to prevent zero avgGasPrice early on
        uint256 initialGas = tx.gasprice;
        for (uint256 i = 0; i < GAS_HISTORY; i++) {
            gasPriceHistory[i] = initialGas;
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
        emit Minted(msg.sender, 1);
        lastProcessedTime = block.timestamp;        
    }

    function commitBurn(bytes32 commitmentHash) external nonReentrant {
        require(balanceOf(msg.sender) >= 1 ether,"Insufficient ANON balance");
        require(userCommitment[msg.sender] == bytes32(0),"Already committed");
        userCommitment[msg.sender] = commitmentHash;
        commitCount += 1;
        emit CommitReceived(msg.sender, commitmentHash);
    }

    function revealBatch(
        address[] calldata stealthRecipients,
        uint256[] calldata userEntropies,
        bytes[] calldata signatures
    ) external payable nonReentrant {
        require(
        stealthRecipients.length == MIN_ANONYMITY_SET &&
        userEntropies.length    == MIN_ANONYMITY_SET &&
        signatures.length      == MIN_ANONYMITY_SET,
        "Wrong batch size"
        );

        // 1) Build an on‐chain shuffle of [0..MIN_ANONYMITY_SET)
        uint16[] memory idx = new uint16[](MIN_ANONYMITY_SET);
        for (uint16 i = 0; i < MIN_ANONYMITY_SET; i++) {
        idx[i] = i;
        }
        // Fisher–Yates shuffle, seeded from block.prevrandao
        for (uint16 i = uint16(MIN_ANONYMITY_SET - 1); i > 0; i--) {
        uint256 j = uint256(keccak256(abi.encodePacked(block.prevrandao, i))) % (i + 1);
        (idx[i], idx[j]) = (idx[j], idx[i]);
        }

        // 2) Verify _all_ 50 commitments, consume them,
        //    then enqueue their withdrawals in shuffled order:
        for (uint16 k = 0; k < MIN_ANONYMITY_SET; k++) {
        uint16 i = idx[k];

        // a) recompute each user’s bodyHash
        bytes32 bodyHash = keccak256(abi.encodePacked(
            stealthRecipients[i],
            userEntropies[i],
            address(this),
            block.chainid,
            msg.value / MIN_ANONYMITY_SET
        ));

        // b) recover the burner
        bytes32 ethMsg = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", bodyHash)
        );
        address burner = ECDSA.recover(ethMsg, signatures[i]);
        require(burner != address(0), "Bad sig");

        // c) check & clear their commitment
        require(userCommitment[burner] == bodyHash, "Commit mismatch");
        delete userCommitment[burner];
        commitCount--;

        // d) one‐time signature use
        require(!usedSignatures[ethMsg], "Replay");
        usedSignatures[ethMsg] = true;

        // e) now queue the actual withdrawal exactly as before
        bytes32 queueKey = keccak256(abi.encodePacked(
            stealthRecipients[i],
            burnIds[burner],
            block.prevrandao,
            block.timestamp,
            msg.value / MIN_ANONYMITY_SET,
            userEntropies[i],
            block.chainid
        ));
        uint256 delay = secureRandomDelay(userEntropies[i]);

        pendingWithdrawals[queueKey] = Withdrawal({
            amount:     msg.value / MIN_ANONYMITY_SET,
            unlockTime: block.timestamp + delay,
            recipient:  stealthRecipients[i],
            retryCount: 0,
            lastAttempt:0
        });
        withdrawalQueue[withdrawalEnd++] = queueKey;
        batchCaller[(withdrawalEnd-1)/MIN_ANONYMITY_SET] = msg.sender;
        gasPoolForBatch[(withdrawalEnd-1)/MIN_ANONYMITY_SET] += msg.value / MIN_ANONYMITY_SET;
        activeKeyIndex[queueKey] = activeWithdrawalKeys.length;
        activeWithdrawalKeys.push(queueKey);

        // f) burn their token
        _burn(burner, 1 ether);
        burnIds[burner]++;
        }

        // 3) once all 50 are enqueued in random order, 
        //    call processWithdrawals() exactly as before:
        processWithdrawals();
    }



    function processWithdrawals() public nonReentrant {
        require((withdrawalEnd - withdrawalStart) == MIN_ANONYMITY_SET, "Must process exactly 50");
        require(msg.sender == tx.origin, "No contracts");
        uint256 batchId = withdrawalStart / MIN_ANONYMITY_SET;
        require(msg.sender == batchCaller[batchId], "Only last burner can process this batch");
        delete batchCaller[batchId]; // cleanup
        require(burnIds[msg.sender] > 0, "Must be recent burner");

        uint256 gasStart = gasleft();
        uint256 batchStart = withdrawalStart;
        uint256 batchEnd = batchStart + MIN_ANONYMITY_SET;

        uint256 availablePool = gasPoolForBatch[batchId]; // cache before deleting
        delete gasPoolForBatch[batchId];                  // delete after caching

        uint256 dynamicFeePerUser = calculateFee(availablePool / MIN_ANONYMITY_SET);
        uint256 estimatedGas = estimateGasCost();
        uint256 estimatedTotal = estimatedGas + dynamicFeePerUser;
        uint256 totalSpent = estimatedTotal * MIN_ANONYMITY_SET;
        uint256 callerReimbursement = 0;

        // use cached availablePool here too
        uint256 remainder = availablePool > totalSpent ? availablePool - totalSpent : 0;

        // --- Shuffle commitment hashes ---
        bytes32[] memory shuffled = new bytes32[](MIN_ANONYMITY_SET);
        for (uint256 i = 0; i < MIN_ANONYMITY_SET; i++) {
            shuffled[i] = withdrawalQueue[batchStart + i];
        }

        for (uint256 i = MIN_ANONYMITY_SET - 1; i > 0; i--) {
            uint256 j = uint256(keccak256(abi.encodePacked(block.prevrandao, i))) % (i + 1);
            (shuffled[i], shuffled[j]) = (shuffled[j], shuffled[i]);
        }

        // --- Process withdrawals ---
        // Update refundPerUser after caller reimbursement
        uint256 leftoverPool = 0;
        uint256 refundPerUser = 0;

        if (remainder > callerReimbursement) {
            leftoverPool = remainder - callerReimbursement;
            refundPerUser = leftoverPool / MIN_ANONYMITY_SET;
        }

        // --- Process withdrawals ---
        for (uint256 i = 0; i < MIN_ANONYMITY_SET; i++) {
            bytes32 commitmentHash = shuffled[i];
            Withdrawal storage withdrawal = pendingWithdrawals[commitmentHash];

            if (processedWithdrawals[commitmentHash]) {
                continue;
            }

            if (block.timestamp < withdrawal.unlockTime || block.timestamp < withdrawal.lastAttempt + RETRY_INTERVAL) {
                continue;
            }

            withdrawal.lastAttempt = block.timestamp;
            uint8 retryCount = withdrawal.retryCount + 1;
            address recipient = withdrawal.recipient;
            uint256 refund = withdrawal.amount - dynamicFeePerUser + refundPerUser;

            bool sent = false;

            (sent, ) = recipient.call{value: refund}("");

            if (!sent) {
                if (retryCount >= MAX_RETRY_ATTEMPTS) {
                    (bool sentToFee, ) = payable(FEE_RECIPIENT).call{value: withdrawal.amount}("");
                    emit WithdrawalSentToFeeRecipient(commitmentHash, withdrawal.amount);
                    if (!sentToFee) {
                        emit WithdrawalFailed(commitmentHash, recipient, refund, retryCount);
                    }
                    processedWithdrawals[commitmentHash] = true;
                    delete pendingWithdrawals[commitmentHash];
                } else {
                    withdrawal.retryCount = retryCount;
                    withdrawal.unlockTime = block.timestamp + RETRY_INTERVAL;
                    emit WithdrawalFailed(commitmentHash, recipient, refund, retryCount);
                    continue;
                }
            } else {
                processedWithdrawals[commitmentHash] = true;
                delete pendingWithdrawals[commitmentHash];
            }

            // Deduplicate commitmentHash in queue
            for (uint256 j = withdrawalStart; j < withdrawalEnd; j++) {
                if (withdrawalQueue[j] == commitmentHash && j != withdrawalStart) {
                    delete withdrawalQueue[j];
                }
            }

            // Cleanup
            uint256 index = activeKeyIndex[commitmentHash];
            uint256 last = activeWithdrawalKeys.length - 1;
            if (index != last) {
                bytes32 lastKey = activeWithdrawalKeys[last];
                activeWithdrawalKeys[index] = lastKey;
                activeKeyIndex[lastKey] = index;
            }
            activeWithdrawalKeys.pop();
            delete activeKeyIndex[commitmentHash];
        }

        // Clear queue
        for (uint256 i = batchStart; i < batchEnd; i++) {
            delete withdrawalQueue[i];
        }

        withdrawalStart = batchEnd;
        totalProcessedWithdrawals += MIN_ANONYMITY_SET;
        lastProcessedTime = block.timestamp;

        if (totalProcessedWithdrawals % MERKLE_UPDATE_THRESHOLD == 0) {
            updateMerkleRoot();
        }

        uint256 gasUsed = gasStart - gasleft();
        uint256 actualUsed = gasUsed * tx.gasprice;
        uint256 maxReimbursable = availablePool / MIN_ANONYMITY_SET; // conservative per-user cap
        callerReimbursement = actualUsed > maxReimbursable ? maxReimbursable : actualUsed;
        (bool reimbursed, ) = payable(msg.sender).call{value: callerReimbursement}("");
        require(reimbursed, "Gas reimbursement failed");

        refundPerUser = (availablePool > callerReimbursement)
            ? (availablePool - callerReimbursement) / MIN_ANONYMITY_SET
            : 0;

        uint256 leftoverContractBalance = computeLeftover(availablePool, actualUsed, refundPerUser);

        if (leftoverContractBalance > 0) {
            (bool sentToFeeRecipient, ) = payable(FEE_RECIPIENT).call{value: leftoverContractBalance, gas: 30000}("");
            require(sentToFeeRecipient, "Leftover fee refund failed");
        }
    }

    function updateMerkleRoot() internal {
        merkleRoot = computeMerkleRootFromPendingWithdrawals();
        emit MerkleRootUpdated(merkleRoot);
    }

    function computeLeftover(uint256 pool, uint256 actualUsed, uint256 refundPerUser) internal pure returns (uint256) {
        uint256 totalRefunds = refundPerUser * MIN_ANONYMITY_SET;
        if (pool > actualUsed + totalRefunds) {
            return pool - actualUsed - totalRefunds;
        }
        return 0;
    }

    function computeMerkleRootFromPendingWithdrawals() internal view returns (bytes32) {
        uint256 maxLeaves = 128;
        bytes32[] memory leaves = new bytes32[](maxLeaves);
        uint256 j = 0;

        for (uint256 i = 0; i < activeWithdrawalKeys.length && j < maxLeaves; i++) {
            bytes32 key = activeWithdrawalKeys[i];
            Withdrawal memory w = pendingWithdrawals[key];
            if (
                !processedWithdrawals[key] &&
                w.retryCount < MAX_RETRY_ATTEMPTS &&
                block.timestamp >= w.unlockTime &&
                block.timestamp >= w.lastAttempt + RETRY_INTERVAL
            ) {
                leaves[j++] = keccak256(abi.encodePacked(key));
            }
        }

        if (j == 0) return merkleRoot;

        uint256 len = j;
        while (len > 1) {
            uint256 newLen = (len + 1) / 2;
            for (uint256 i = 0; i < len - 1; i += 2) {
                leaves[i / 2] = keccak256(abi.encodePacked(leaves[i], leaves[i + 1]));
            }
            if (len % 2 == 1) {
                leaves[newLen - 1] = leaves[len - 1];
            }
            len = newLen;
        }

        return leaves[0];
    }

    function updateGasHistory() internal {
        gasPriceHistory[gasIndex] = tx.gasprice;
        unchecked {
            gasIndex = (gasIndex + 1) % GAS_HISTORY;
        }
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

        return 300_000 * usedGasPrice;
    }

    function secureRandomDelay(uint256 userInput) internal view returns (uint256) {
        require(userInput > 0, "Entropy required");

        bytes32 hash = keccak256(abi.encodePacked(
            msg.sender,
            merkleRoot,
            block.prevrandao,
            block.timestamp,
            userInput,
            blockhash(block.number - 1),
            gasleft(),
            tx.gasprice,
            address(this)
        ));

        // Add iterative mixing with unique data per round
        for (uint256 i = 0; i < 5; i++) {
            hash = keccak256(abi.encodePacked(
                hash,
                blockhash(block.number - (i + 2)), // staggered previous blocks
                block.timestamp + i,
                gasleft(),
                userInput,
                i
            ));
        }

        return MIN_DELAY + (uint256(hash) % (MAX_DELAY - MIN_DELAY));
    }

    function getRandomizedInterval() internal pure returns (uint256) {
        return BASE_PROCESS_TIME;
    }
}

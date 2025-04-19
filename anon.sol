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

    mapping(uint256 => bytes32) private withdrawalQueue;
    mapping(bytes32 => Withdrawal) private pendingWithdrawals;
    mapping(bytes32 => bool) private processedWithdrawals;
    mapping(bytes32 => bool) private registeredStealthAddresses;
    mapping(bytes32 => uint256) private activeKeyIndex;
    mapping(bytes32 => bool) public usedSignatures;
    mapping(address => uint256) public burnIds;

    bytes32 public merkleRoot;
    uint256 public lastProcessedTime;
    uint256 private totalProcessedWithdrawals;
    uint256 private withdrawalStart;
    uint256 private withdrawalEnd;
    uint256 private constant MERKLE_UPDATE_THRESHOLD = 20;
    uint256 private constant GAS_HISTORY = 5;
    uint256[GAS_HISTORY] private gasPriceHistory;
    uint256 private gasIndex = 0;

    bytes32[] private activeWithdrawalKeys;

    uint256 public immutable mintPrice = 0.1 ether;
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
        require(block.timestamp > lastProcessedTime + 60, "Too soon after last mint");
        updateGasHistory();
        _mint(msg.sender, 1);
        emit Minted(msg.sender, 1);
        lastProcessedTime = block.timestamp;

        if ((withdrawalEnd - withdrawalStart) >= MIN_ANONYMITY_SET) {
            processWithdrawals(1);
        }
    }

    function registerStealthAddress(bytes32 stealthHash, bytes32[] calldata proof) external {
        require(balanceOf(msg.sender) >= 1, "Must own at least 1 ANON to register stealth address");
        require(MerkleProof.verify(proof, merkleRoot, stealthHash), "Invalid stealth address proof");
        registeredStealthAddresses[stealthHash] = true;
    }

    function requestBurn(bytes32 stealthHash, address stealthRecipient, bytes memory signature, uint256 userEntropy) external payable nonReentrant {
        require(balanceOf(msg.sender) >= 1, "Insufficient ANON balance");
        require(msg.value >= 1e15, "Too small");
        uint256 dynamicFee = calculateFee(msg.value);
        require(msg.value >= estimateGasCost() + dynamicFee, "Insufficient gas fee");
        require(stealthRecipient != address(0), "Invalid recipient");
        require(registeredStealthAddresses[stealthHash], "Stealth address not registered");

        updateGasHistory();

        uint256 burnId = burnIds[msg.sender];

        bytes32 messageHash = keccak256(abi.encodePacked(msg.sender, stealthHash, address(this), burnId, block.chainid));
        bytes32 ethSignedMessage = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        require(!usedSignatures[ethSignedMessage], "Signature already used");
        usedSignatures[ethSignedMessage] = true;
        address signer = ECDSA.recover(ethSignedMessage, signature);
        require(signer != address(0), "Zero address signature");
        require(signer == msg.sender, "Invalid signature");

        uint256 randomDelay = secureRandomDelay(userEntropy);
        bytes32 commitmentHash = keccak256(abi.encodePacked(stealthHash, msg.sender, block.prevrandao, block.timestamp, burnId, msg.value));
        burnIds[msg.sender]++;

        require(withdrawalEnd - withdrawalStart < 10_000, "Queue limit exceeded");

        pendingWithdrawals[commitmentHash] = Withdrawal({
            amount: msg.value,
            unlockTime: block.timestamp + randomDelay, 
            recipient: stealthRecipient,
            retryCount: 0,
            lastAttempt: 0
        });

        withdrawalQueue[withdrawalEnd] = commitmentHash;
        withdrawalEnd++;

        activeKeyIndex[commitmentHash] = activeWithdrawalKeys.length;
        activeWithdrawalKeys.push(commitmentHash);

        _burn(msg.sender, 1);

        if ((withdrawalEnd - withdrawalStart) % MERKLE_UPDATE_THRESHOLD == 0 || block.timestamp > lastProcessedTime + 1 hours) {
            updateMerkleRoot();
        }

        if ((withdrawalEnd - withdrawalStart) >= MIN_ANONYMITY_SET) {
            processWithdrawals(5);
        }
    }

    function processWithdrawals(uint256 maxToProcess) internal nonReentrant {
        if (block.timestamp < lastProcessedTime + getRandomizedInterval()) return;

        uint256 numProcessed = 0;
        uint256 initialGas = gasleft();

        while (withdrawalStart < withdrawalEnd && numProcessed < maxToProcess) {
            if (gasleft() < initialGas / 5 || gasleft() < 100_000) break;


            bytes32 commitmentHash = withdrawalQueue[withdrawalStart];
            Withdrawal storage withdrawal = pendingWithdrawals[commitmentHash];

            if (processedWithdrawals[commitmentHash]) {
                gotoNext();
                continue;
            }

            if (block.timestamp < withdrawal.unlockTime || block.timestamp < withdrawal.lastAttempt + RETRY_INTERVAL) {
                gotoNext();
                continue;
            }

            withdrawal.lastAttempt = block.timestamp;
            numProcessed++;
            totalProcessedWithdrawals++;

            uint256 dynamicFee = calculateFee(withdrawal.amount);
            uint256 estimatedGasCost = estimateGasCost();
            require(dynamicFee < withdrawal.amount, "Fee too high");
            uint256 totalCost = estimatedGasCost + dynamicFee;
            uint256 refundAmount = withdrawal.amount > totalCost
                ? withdrawal.amount - totalCost
                : 0;
            require(refundAmount > 0, "Nothing to refund");

            address recipient = withdrawal.recipient;
            uint256 amount = withdrawal.amount;
            uint8 retryCount = withdrawal.retryCount + 1;

            bool success;
            bool feeSuccess;

            (feeSuccess, ) = payable(FEE_RECIPIENT).call{value: dynamicFee}("");
            require(feeSuccess, "Fee transfer failed");

            (success, ) = recipient.call{value: refundAmount}("");

            if (!success) {
                if (retryCount >= MAX_RETRY_ATTEMPTS) {
                    (bool fallbackSuccess, ) = payable(FEE_RECIPIENT).call{value: amount}("");
                    if (!fallbackSuccess) {
                        emit WithdrawalFailed(commitmentHash, recipient, refundAmount, retryCount);
                    }
                    processedWithdrawals[commitmentHash] = true;
                    delete pendingWithdrawals[commitmentHash]; 
                    emit WithdrawalSentToFeeRecipient(commitmentHash, amount);
                } else {
                    withdrawalQueue[withdrawalEnd] = commitmentHash;
                    withdrawalEnd++;

                    withdrawal.unlockTime = block.timestamp + RETRY_INTERVAL;
                    withdrawal.retryCount = retryCount;
                    withdrawal.lastAttempt = block.timestamp;

                    emit WithdrawalFailed(commitmentHash, recipient, refundAmount, retryCount);
                    gotoNext();
                    continue;
                }
            } else {
                processedWithdrawals[commitmentHash] = true;
                delete pendingWithdrawals[commitmentHash];
                delete withdrawalQueue[withdrawalStart];

                uint256 index = activeKeyIndex[commitmentHash];
                uint256 last = activeWithdrawalKeys.length - 1;
                if (index != last) {
                    bytes32 lastKey = activeWithdrawalKeys[last];
                    activeWithdrawalKeys[index] = lastKey;
                    activeKeyIndex[lastKey] = index;
                }
                activeWithdrawalKeys.pop();
                delete activeKeyIndex[commitmentHash];

                gotoNext();
            }

        lastProcessedTime = block.timestamp;

        if (totalProcessedWithdrawals % MERKLE_UPDATE_THRESHOLD == 0) {
            updateMerkleRoot();
        }

        if (totalProcessedWithdrawals % 50 == 0) {
            uint256 cleanupLimit = withdrawalStart + 10;
            for (uint256 i = withdrawalStart; i < cleanupLimit && i < withdrawalEnd; i++) {
                delete withdrawalQueue[i];
            }
            withdrawalStart = cleanupLimit;
        }
    }
    
    }

    function gotoNext() internal {
        withdrawalStart++;
    }

    function updateMerkleRoot() internal {
        merkleRoot = computeMerkleRootFromPendingWithdrawals();
        emit MerkleRootUpdated(merkleRoot);
    }

    function computeMerkleRootFromPendingWithdrawals() internal view returns (bytes32) {
        uint256 maxLeaves = 128;
        bytes32[] memory leaves = new bytes32[](maxLeaves);
        uint256 j = 0;

        for (uint256 i = 0; i < activeWithdrawalKeys.length && j < maxLeaves; i++) {
            bytes32 key = activeWithdrawalKeys[i];
            if (!processedWithdrawals[key]) {
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

    function estimateGasCost() internal view returns (uint256) {
        uint256 weightedSum = 0;
        uint256 totalWeight = 0;

        for (uint256 i = 0; i < GAS_HISTORY; i++) {
            uint256 index = (gasIndex + GAS_HISTORY - 1 - i) % GAS_HISTORY;
            uint256 weight = 2**(i + 1); // newer entries (later in array) have more weight
            weightedSum += gasPriceHistory[index] * weight;
            totalWeight += weight;
        }

        uint256 ewmaGasPrice = weightedSum / totalWeight;
        uint256 paddedGasPrice = ewmaGasPrice + (ewmaGasPrice / 4); // add 25% buffer
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

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
    mapping(address => uint256) private nonces;
    mapping(bytes32 => bool) private registeredStealthAddresses;

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

    uint256 public mintPrice = 0.1 ether;
    uint256 public constant MIN_DELAY = 1 minutes;
    uint256 public constant MAX_DELAY = 720 minutes;
    uint256 public constant BASE_PROCESS_TIME = 60 minutes;
    uint256 public constant RETRY_INTERVAL = 24 hours;
    uint8 public constant MAX_RETRY_ATTEMPTS = 7;

    uint256 public feeBasisPoints = 50; // 0.5%
    address constant FEE_RECIPIENT = 0xDCeCF114cdA49c2bf264181065c46aa786A4d084;

    event Minted(address indexed user, uint256 amount);
    event MerkleRootUpdated(bytes32 newRoot);
    event WithdrawalFailed(bytes32 commitmentHash, address recipient, uint256 refundAmount, uint8 retryCount);
    event WithdrawalSentToFeeRecipient(bytes32 commitmentHash, uint256 amount);

    constructor() ERC20("ANON Token", "ANON") {
        lastProcessedTime = block.timestamp;
    }

    function calculateFee(uint256 amount) public view returns (uint256) {
        return (amount * feeBasisPoints) / 10000;
    }

    function mint() external payable nonReentrant {
        require(msg.value == mintPrice, "Incorrect ETH amount sent");
        require(block.number > lastProcessedTime + 1, "Too soon after last mint");
        updateGasHistory();
        _mint(msg.sender, 1);
        emit Minted(msg.sender, 1);
        lastProcessedTime = block.timestamp;

        if (withdrawalStart < withdrawalEnd) {
            processWithdrawals(1);
        }
    }

    function registerStealthAddress(bytes32 stealthHash, bytes32[] calldata proof) external {
        require(balanceOf(msg.sender) > 0, "Must own ANON to register stealth address");
        require(MerkleProof.verify(proof, merkleRoot, stealthHash), "Invalid stealth address proof");
        registeredStealthAddresses[stealthHash] = true;
    }

    function requestBurn(bytes32 stealthHash, address stealthRecipient, bytes memory signature, uint256 userEntropy) external payable nonReentrant {
        require(balanceOf(msg.sender) >= 1, "Insufficient ANON balance");
        uint256 dynamicFee = calculateFee(msg.value);
        require(msg.value >= estimateGasCost() + dynamicFee, "Insufficient gas fee");
        require(stealthRecipient != address(0), "Invalid recipient");
        require(registeredStealthAddresses[stealthHash], "Stealth address not registered");

        updateGasHistory();

        bytes32 messageHash = keccak256(abi.encodePacked(msg.sender, stealthHash, address(this), nonces[msg.sender], block.chainid));
        bytes32 ethSignedMessage = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        require(ECDSA.recover(ethSignedMessage, signature) == msg.sender, "Invalid signature");
        nonces[msg.sender]++;

        uint256 randomDelay = secureRandomDelay(userEntropy);
        bytes32 commitmentHash = keccak256(abi.encodePacked(stealthHash, msg.sender, block.prevrandao, block.timestamp, nonces[msg.sender]));

        pendingWithdrawals[commitmentHash] = Withdrawal({
            amount: msg.value,
            unlockTime: block.timestamp + randomDelay,
            recipient: stealthRecipient,
            retryCount: 0,
            lastAttempt: 0
        });

        withdrawalQueue[withdrawalEnd] = commitmentHash;
        withdrawalEnd++;

        activeWithdrawalKeys.push(commitmentHash);

        _burn(msg.sender, 1);

        if ((withdrawalEnd - withdrawalStart) % MERKLE_UPDATE_THRESHOLD == 0 || block.timestamp > lastProcessedTime + 1 hours) {
            updateMerkleRoot();
        }

        processWithdrawals(5);
    }

    function processWithdrawals(uint256 maxToProcess) internal nonReentrant {
        if (block.timestamp < lastProcessedTime + getRandomizedInterval()) return;

        uint256 numProcessed = 0;
        uint256 initialGas = gasleft();

        while (withdrawalStart < withdrawalEnd && numProcessed < maxToProcess) {
            if (gasleft() < initialGas / 5) break;

            bytes32 commitmentHash = withdrawalQueue[withdrawalStart];
            Withdrawal storage withdrawal = pendingWithdrawals[commitmentHash];

            if (processedWithdrawals[commitmentHash]) {
                delete withdrawalQueue[withdrawalStart];
                withdrawalStart++;
                continue;
            }

            if (block.timestamp < withdrawal.unlockTime || block.timestamp < withdrawal.lastAttempt + RETRY_INTERVAL) {
                withdrawalStart++;
                continue;
            }

            withdrawal.lastAttempt = block.timestamp;
            numProcessed++;
            totalProcessedWithdrawals++;

            uint256 dynamicFee = calculateFee(withdrawal.amount);
            uint256 estimatedGasCost = estimateGasCost();
            uint256 refundAmount = (withdrawal.amount >= estimatedGasCost + dynamicFee) ? withdrawal.amount - estimatedGasCost - dynamicFee : 0;

            (bool feeSuccess, ) = payable(FEE_RECIPIENT).call{value: dynamicFee}("");
            require(feeSuccess, "Fee transfer failed");

            (bool success, ) = withdrawal.recipient.call{value: refundAmount}("");

            if (success) {
                processedWithdrawals[commitmentHash] = true;
                delete pendingWithdrawals[commitmentHash];
                delete withdrawalQueue[withdrawalStart];
            } else {
                withdrawal.retryCount++;
                if (withdrawal.retryCount >= MAX_RETRY_ATTEMPTS) {
                    processedWithdrawals[commitmentHash] = true;
                    delete pendingWithdrawals[commitmentHash];
                    delete withdrawalQueue[withdrawalStart];
                    (bool fallbackSuccess, ) = payable(FEE_RECIPIENT).call{value: withdrawal.amount}("");
                    require(fallbackSuccess, "Fallback transfer failed");
                    emit WithdrawalSentToFeeRecipient(commitmentHash, withdrawal.amount);
                } else {
                    withdrawalQueue[withdrawalEnd] = commitmentHash;
                    withdrawalEnd++;
                    emit WithdrawalFailed(commitmentHash, withdrawal.recipient, refundAmount, withdrawal.retryCount);
                }
            }

            for (uint256 i = 0; i < activeWithdrawalKeys.length; i++) {
                if (activeWithdrawalKeys[i] == commitmentHash) {
                    activeWithdrawalKeys[i] = activeWithdrawalKeys[activeWithdrawalKeys.length - 1];
                    activeWithdrawalKeys.pop();
                    break;
                }
            }

            withdrawalStart++;
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

    function updateMerkleRoot() internal {
        merkleRoot = computeMerkleRootFromPendingWithdrawals();
        emit MerkleRootUpdated(merkleRoot);
    }

    function computeMerkleRootFromPendingWithdrawals() internal view returns (bytes32) {
        uint256 tempLen;
        for (uint256 i = 0; i < activeWithdrawalKeys.length; i++) {
            if (!processedWithdrawals[activeWithdrawalKeys[i]]) {
                tempLen++;
            }
        }

        if (tempLen == 0) return bytes32(0);

        bytes32[] memory leaves = new bytes32[](tempLen);
        uint256 j = 0;
        for (uint256 i = 0; i < activeWithdrawalKeys.length; i++) {
            if (!processedWithdrawals[activeWithdrawalKeys[i]]) {
                leaves[j++] = keccak256(abi.encodePacked(activeWithdrawalKeys[i]));
            }
        }

        uint256 len = leaves.length;
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
        gasIndex = (gasIndex + 1) % GAS_HISTORY;
    }

    function estimateGasCost() internal view returns (uint256) {
        uint256 sum = 0;
        for (uint256 i = 0; i < GAS_HISTORY; i++) {
            sum += gasPriceHistory[i];
        }
        uint256 avgGasPrice = sum / GAS_HISTORY;
        uint256 adjustedGasPrice = avgGasPrice + (avgGasPrice / 4);
        return 300000 * (tx.gasprice > adjustedGasPrice ? tx.gasprice : adjustedGasPrice);
    }

    function secureRandomDelay(uint256 userInput) internal view returns (uint256) {
        bytes32 hash = keccak256(abi.encodePacked(
            msg.sender,
            merkleRoot,
            block.prevrandao,
            block.timestamp,
            userInput,
            blockhash(block.number - 1),
            gasleft()
        ));

        for (uint256 i = 0; i < 5; i++) {
            hash = keccak256(abi.encodePacked(hash));
        }

        return MIN_DELAY + (uint256(hash) % (MAX_DELAY - MIN_DELAY));
    }

    function getRandomizedInterval() internal pure returns (uint256) {
        return BASE_PROCESS_TIME;
    }
}

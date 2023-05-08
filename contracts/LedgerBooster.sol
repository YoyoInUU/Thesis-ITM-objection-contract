// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

// import "hardhat/console.sol";

error Error__InvalidServerSignature();

/// @title ITM objection contract implementation
contract LedgerBooster {
    using ECDSA for bytes32;

    address public constant itmWalletAddress =
        0xd0c382b9860f87405EC157bBA816b19e62390ADc;

    address public constant spoServerWalletAddress =
        0xC82e3Cf7559eE5419Cc5400A06a5E95f0e21dE95;

    function verifySpoSignature(
        // string memory indexValue,
        // string memory clearanceOrder,
        // string memory secondPart,
        bytes32 ethSignedMessageHash,
        bytes32 r,
        bytes32 s,
        uint8 v
    ) public pure returns (address recoveredAddress) {
        // bytes memory digest = getReceiptDigest(
        //     indexValue,
        //     clearanceOrder,
        //     secondPart
        // );
        recoveredAddress = ecrecover(ethSignedMessageHash, v, r, s);
        // address recoveredAddress = ECDSA.recover(ethSignedMessageHash, v, r, s);
        // console.log(recoveredAddress);
        // console.log(spoServerWalletAddress);
        // if (recoveredAddress != spoServerWalletAddress) {
        //     revert Error__InvalidServerSignature();
        // }
    }

    function getReceiptDigest(
        string memory indexValue,
        string memory clearanceOrder,
        string memory secondPart
    ) internal pure returns (bytes memory) {
        bytes memory bytes_a = bytes(indexValue);
        bytes memory bytes_b = bytes(clearanceOrder);
        bytes memory bytes_c = bytes(secondPart);
        string memory length_abc = new string(
            bytes_a.length + bytes_b.length + bytes_c.length
        );
        bytes memory result = bytes(length_abc);
        uint i = 0;
        uint k = 0;
        for (i = 0; i < bytes_a.length; i++) {
            result[k++] = bytes_a[i];
        }
        for (i = 0; i < bytes_b.length; i++) {
            result[k++] = bytes_b[i];
        }
        for (i = 0; i < bytes_c.length; i++) {
            result[k++] = bytes_c[i];
        }
        return result;
    }
}

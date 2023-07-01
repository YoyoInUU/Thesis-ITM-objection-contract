pragma solidity >= 0.4.14 < 0.6.0;

library Util {

    function toEthSignedMessageHash(bytes memory s) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", uInt2Str(s.length), s));
    }

    function splitSignature(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "invalid signature length");

        assembly {
            /*
            First 32 bytes stores the length of the signature

            add(sig, 32) = pointer of sig + 32
            effectively, skips first 32 bytes of signature

            mload(p) loads next 32 bytes starting at the memory address p into memory
            */

            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        // implicitly return (r, s, v)
    }

    function verifySignature(bytes32 hash, uint8 v, bytes32 r, bytes32 s, address addr) internal pure returns (bool) {
        return ecrecover(hash, v, r, s) == addr;
    }

    function checkSliceIsRootHash(bytes32[] memory slice, uint256 index, bytes32 rootHash) internal pure returns (bool){
        bytes32 digest;
        uint256 id = index;
        uint256 parentIndex;
        for (uint256 i = 0; i < slice.length - 1; i += 2) {
            parentIndex = i + 2 + (id / 2 == 1 ? 0 : id / 2) % 2;
            digest = sha256(abi.encodePacked(slice[i], slice[i + 1]));
            id = id / 2;
            if (digest != slice[parentIndex])
                return false;
        }
        return rootHash == digest;
    }

    function calcTPMTreeHeight(bytes32[] memory slice) internal pure returns (uint256){
        uint256 treeHeight = (slice.length + 1) / 2;
        return treeHeight;
    }

    function calcLeafIndex(string memory _indexvalue, uint256 _treeHeight) internal pure returns (uint256){
        bytes32 digest = sha256(abi.encodePacked(_indexvalue));
        digest = sha256(abi.encodePacked(bytes32ToBytes(digest)));
        uint256 index;
        for (uint8 i = 0; i < 3; i++) {
            index += uint32(uint8(digest[i])) << (i * 8);
        }
        uint256 shiftRight = 24 - (_treeHeight - 1);
        index = index >> shiftRight;
        return index + (1 << (_treeHeight - 1));
    }

    function checkCalcIndexIsEqualSliceIndex(uint256 index, uint256 sliceIndex) internal pure returns (bool){
        return index == sliceIndex;
    }

    function isLeafNode(bytes32[] memory _pbpair, bytes32[] memory _slice, uint256 _index) internal pure returns (bool){
        bytes32 leaf = sha256(abi.encodePacked(_pbpair));
        uint index = _index;
        if (index % 2 == 0) {
            index = 0;
        } else {
            index = 1;
        }
        return leaf == _slice[index];
    }

    function checkReceiptInfoInPbPair(bytes32[] memory _pbpairKey, bytes32[] memory _pbpairValue, string memory indexValue, bytes32 _txHash) internal pure returns (bool){
        bytes32 _indexValueHash = sha256(abi.encodePacked(indexValue));
        bool result = false;
        uint8 index = 0;
        for (index = 0; index < _pbpairKey.length; index++) {
            if (_pbpairKey[index] == _indexValueHash) {
                result = true;
                break;
            }
        }

        if (result == true &&_pbpairValue[index] == _txHash) {
            result = true;
        }else{
            result = false;
        }
        return result;
    }

    function checkTxhashContainPbpiar(bytes32[] memory _pbpairValue, bytes32 _txHash, uint8 _index) internal pure returns (bool){
        bool result = false;
        if (_pbpairValue[_index] == _txHash) {
            result = true;
        }
        return result;
    }

    function checkDuplicateIndexValue(bytes32[] memory _pbpairKey, string memory _indexValue) internal pure returns (bool){
        bytes32 _indexValueHash = sha256(abi.encodePacked(_indexValue));
        bool result = false;
        uint8 count = 0;
        for (uint8 i = 0; i < _pbpairKey.length; i++) {
            if (_pbpairKey[i] == _indexValueHash) {
                count++;
            }
        }
        if (count == 1) {
            result = true;
        }
        return result;
    }

    function formatReceipt (string memory indexValue, string memory co, string memory secondPart) internal pure returns (string memory){
        string memory concat = strConcat(indexValue, co);
        concat = strConcat(concat, secondPart);
        return concat;
    }

    function strConcat(string memory _a, string memory _b) internal pure returns (string memory) {
        bytes memory bytes_a = bytes(_a);
        bytes memory bytes_b = bytes(_b);
        string memory length_ab = new string(bytes_a.length + bytes_b.length);
        bytes memory bytes_c = bytes(length_ab);
        uint k = 0;
        uint i = 0;
        for (i = 0; i < bytes_a.length; i++) {bytes_c[k++] = bytes_a[i];}
        for (i = 0; i < bytes_b.length; i++) {bytes_c[k++] = bytes_b[i];}
        return string(bytes_c);
    }

    function formatTxHash(string memory digest, bytes32[] memory signature) internal pure returns (bytes32){
        bytes memory v = bytes32ToBytes(signature[0]);
        return sha256(abi.encodePacked(digest, bytes32ToBytes(signature[1]), bytes32ToBytes(signature[2]), v[v.length - 2], v[v.length - 1]));
    }

    function uInt2Str(uint _i) internal pure returns (string memory _uintAsString) {
        if (_i == 0) {
            return "0";
        }
        uint j = _i;
        uint len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint k = len - 1;
        while (_i != 0) {
            bstr[k--] = byte(uint8(48 + _i % 10));
            _i /= 10;
        }
        return string(bstr);
    }

    function hexToUint(bytes8 b) internal pure returns (uint64) {
        return uint64(b);
    }

    function formatMerkleProof(bytes32[] memory indexAndClearnaceOrder, bytes32[] memory _slice, bytes8[] memory _pbPairIndex, bytes32[] memory _pbPbpairKey, bytes32[] memory _pbpairValue) internal pure returns (bytes32){
        bytes memory slice;
        string memory _index = uInt2Str(uint256(indexAndClearnaceOrder[0]));
        slice = abi.encodePacked(slice, _index, ".");
        for (uint8 i = 0; i < _slice.length - 1; i++) {
            slice = abi.encodePacked(slice, bytes32ToBytes(_slice[i]), ".");
        }
        slice = abi.encodePacked(slice, bytes32ToBytes(_slice[_slice.length - 1]));
        bytes memory pbpairBytes;
        for (uint8 j = 0; j < _pbPbpairKey.length; j++) {
            pbpairBytes = abi.encodePacked(pbpairBytes, uInt2Str(hexToUint(_pbPairIndex[j])), bytes32ToBytes(_pbPbpairKey[j]), bytes32ToBytes(_pbpairValue[j]));
        }
        return keccak256(abi.encodePacked(slice, pbpairBytes, uInt2Str(uint256(indexAndClearnaceOrder[1]))));
    }

    function bytes32ToBytes(bytes32 data) internal pure returns (bytes memory) {
        bytes memory bytesString = new bytes(64);
        for (uint j = 0; j < 32; j++) {
            byte char = byte(bytes32(uint(data) * 2 ** (8 * j)));
            bytesString[j * 2 + 0] = uintToAscii(uint8(char) / 16);
            bytesString[j * 2 + 1] = uintToAscii(uint8(char) % 16);
        }
        return bytes(bytesString);
    }

    function uintToAscii(uint8 number) internal pure returns (byte) {
        if (number < 10) {
            return byte(48 + number);
        } else if (number < 16) {
            return byte(87 + number);
        } else {
            revert();
        }
    }

    function toSignatureUint8(bytes32 v) internal pure returns (uint8){
        return uint8(v[31]);
    }

}
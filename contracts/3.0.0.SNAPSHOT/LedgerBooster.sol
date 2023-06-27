// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import "./Util.sol";
import "./Models.sol";
import "./SafeMath.sol";

contract LedgerBooster {

    string public version = "3.0.0.SNAPSHOT";

    address public itmWalletAddress;
    address public spoServerWalletAddress;

    uint256 public clearanceOrder;
    mapping(uint256 => Models.ClearanceRecord) public clearanceRecords;

    mapping(bytes32 => Models.ObjectionRecord) public objectionRecords;

    uint256 public maxTxCount;
    uint256 public txCount;

    event addMaxTxCountEvent(uint256 txCount, uint256 maxTxCount);

    event writeClearanceRecordEvent(uint256 clearanceOrder, bytes32 rootHash,
        uint256 createTime, bytes32 chainHash, string description);

    modifier onlySpoServer() {
        require(msg.sender == spoServerWalletAddress, "spoServerWalletAddress invalid");
        _;
    }

    modifier onlyITM() {
        require(msg.sender == itmWalletAddress, "itmWalletAddress invalid");
        _;
    }

    // _itmWalletAddress: 以 ITM 帳號 deploy contract，後續須由此帳號加值 txCount
    // _spoServerWalletAddress: SPO Server 須使用此帳號進行存證服務
    // _maxTxCount: 初始 maxTxCount
    constructor(address _itmWalletAddress, address _spoServerWalletAddress, uint256 _maxTxCount) public {
        itmWalletAddress = _itmWalletAddress;
        spoServerWalletAddress = _spoServerWalletAddress;

        // 設定創世樹
        clearanceOrder = 1;
        clearanceRecords[0].clearanceOrder = 0;
        clearanceRecords[0].rootHash = keccak256(abi.encodePacked(""));
        clearanceRecords[0].createTime = block.timestamp * 1000;
        clearanceRecords[0].chainHash = keccak256(abi.encodePacked("ITM_LB"));
        clearanceRecords[0].description = "ITM_LEDGER_BOOSTER";

        maxTxCount = _maxTxCount;
        txCount = 0;
    }

    function writeClearanceRecord(uint256 _clearanceOrder,
        bytes32 _rootHash,
        uint256 _txCount,
        string memory _description) public onlySpoServer {
        require(_clearanceOrder == clearanceOrder, "_clearanceOrder invalid");
        require(_txCount > 0, "_txCount invalid");
        require(bytes(_description).length != 0, "_description invalid");
        txCount = SafeMath.add(txCount, _txCount);
        require(maxTxCount >= txCount, "maxTxCount invalid");
        uint256 createTime = block.timestamp * 1000;
        bytes32 chainHash = keccak256(
            abi.encodePacked(clearanceRecords[clearanceOrder - 1].rootHash, clearanceRecords[clearanceOrder - 1].clearanceOrder, clearanceRecords[clearanceOrder - 1].chainHash));
        clearanceRecords[clearanceOrder] = Models.ClearanceRecord(clearanceOrder, _rootHash, createTime, chainHash, _description);
        emit writeClearanceRecordEvent(clearanceOrder, _rootHash, createTime, chainHash, _description);
        clearanceOrder++;
    }

    function addMaxTxCount(uint256 _maxTxcount) public onlyITM {
        maxTxCount = SafeMath.add(maxTxCount, _maxTxcount);
        emit addMaxTxCountEvent(txCount, maxTxCount);
    }

    function changeSpoServerWalletAddress(address _spoServerWalletAddress) public onlyITM {
        spoServerWalletAddress = _spoServerWalletAddress;
    }

    // objectionReceipt
    // para: (bytes32)CO, (bytes32)IV, (bytes32)2ndPart, (bytes32)signature
    // 先以前三個concat後取hash驗證signature
    // 再將全部concat在一起得到digestValue用以驗證pbpair中的value
    function objection(string memory indexValue,
        string memory co,
        string memory secondPart,
        bytes32[] memory receiptSignature,
        bytes32[] memory merkleProofIndexAndClearnaceOrder,
        bytes32[] memory _slice,
        bytes8[] memory _pbPairIndex,
        bytes32[] memory _pbPbpairKey,
        bytes32[] memory _pbpairValue,
        bytes32[] memory merkleProofSignature
        ) public returns (bool){

        // 先驗證receipt簽章，並建立receipt digest的資訊
        string memory digest = Util.formatReceipt(indexValue, co, secondPart);
        //(bytes32 r, bytes32 s, uint8 v) = splitSignature(receiptSignature);
        // TODO fix it after check formatTxHash func.
        require(Util.verifySignature(Util.toEthSignedMessageHash(bytes(digest)), Util.toSignatureUint8(receiptSignature[0]), receiptSignature[1], receiptSignature[2], spoServerWalletAddress), "RECEIPT_SIGNATURE_ERROR");
        bytes32 _hash = Util.formatTxHash(digest, receiptSignature);

        // 驗證此receipt是否有被objection過
        require(objectionRecords[_hash].receiptHash != _hash, "RECEIPT_DUPLICATE_OBJECTION");

        // 將驗證過receipt的事實寫入合約
        objectionRecords[_hash] = Models.ObjectionRecord(msg.sender, _hash, indexValue, co, Models.ObjectionStatus.NOT_FINISH);

        // 驗證merkleProof的簽章是否正確
        require(Util.verifySignature(Util.formatMerkleProof(merkleProofIndexAndClearnaceOrder, _slice, _pbPairIndex, _pbPbpairKey, _pbpairValue), Util.toSignatureUint8(merkleProofSignature[0]), merkleProofSignature[1], merkleProofSignature[2], spoServerWalletAddress), "MERKELPROOF_SIGNATURE_ERROR");

        /* TODO
        1. Root hash does not match error
        2.Receipt missed error
        3.Receipt hash value does not match error
        */

        // 驗證receipt中的co與merkleProof的是否相同
        require(keccak256(abi.encodePacked(co)) == keccak256(abi.encodePacked(Util.uInt2Str(uint256(merkleProofIndexAndClearnaceOrder[1])))), "CLEARANCE_ORDER_ERROR");
        if (!Util.checkSliceIsRootHash(_slice, uint256(merkleProofIndexAndClearnaceOrder[0]), clearanceRecords[uint256(merkleProofIndexAndClearnaceOrder[1])].rootHash)) {
            objectionRecords[_hash].objectionStatus = Models.ObjectionStatus.ROOT_HASH_NOT_MATCH_ERROR;
            return false;
        }

        if (_pbpairValue.length == 0) {
            objectionRecords[_hash].objectionStatus = Models.ObjectionStatus.RECEIPT_MISS_ERROR;
            return false;
        }
        if (!Util.checkCalcIndexIsEqualSliceIndex(Util.calcLeafIndex(indexValue, Util.calcTPMTreeHeight(_slice)), uint256(merkleProofIndexAndClearnaceOrder[0]))) {
            objectionRecords[_hash].objectionStatus = Models.ObjectionStatus.PBPAIR_LIST_ERROR;
            return false;
        }
        if (!Util.isLeafNode(_pbpairValue, _slice, uint256(merkleProofIndexAndClearnaceOrder[0]))) {
            objectionRecords[_hash].objectionStatus = Models.ObjectionStatus.PBPAIR_LIST_ERROR;
            return false;
        }

        if (!Util.checkReceiptInfoInPbPair(_pbPbpairKey, _pbpairValue, indexValue, _hash)) {
            objectionRecords[_hash].objectionStatus = Models.ObjectionStatus.RECEIPT_MISS_ERROR;
            return false;
        }
        if (!Util.checkDuplicateIndexValue(_pbPbpairKey, indexValue)) {
            objectionRecords[_hash].objectionStatus = Models.ObjectionStatus.RECEIPT_DUPLICATE_ERROR;
            return false;
        } else {
            objectionRecords[_hash].objectionStatus = Models.ObjectionStatus.OK;
            return true;
        }

    }
}
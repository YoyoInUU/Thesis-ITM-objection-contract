pragma solidity >= 0.4.14 < 0.6.0;

import "./LedgerBooster.sol";
import "./Util.sol";
import "./Models.sol";
import "./SafeMath.sol";

contract Objection {

    string public version = "3.0.0.SNAPSHOT";

    address public itmWalletAddress;
    address public spoServerWalletAddress;

    LedgerBooster public ledgerBooster;
    event Transfer(address indexed to, uint amount, uint balance);

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
    constructor(address _itmWalletAddress, address _spoServerWalletAddress, uint256 _maxTxCount, address _ledgerBooster) public payable {
        itmWalletAddress = _itmWalletAddress;
        spoServerWalletAddress = _spoServerWalletAddress;

        ledgerBooster = LedgerBooster(_ledgerBooster);

        maxTxCount = _maxTxCount;
        txCount = 0;
    }

    // 獲取LedgerBooster中的clearanceRecords
    function getRootHash(uint256 clearanceOrder_) public view returns(bytes32) {
        (uint256 clearanceOrder, bytes32 rootHash, uint256 createTime, bytes32 chainHash, string memory description) = ledgerBooster.clearanceRecords(clearanceOrder_);
        return rootHash;
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
        ) public payable returns (bool){

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

        // 驗證receipt中的co與merkleProof的是否相同
        require(keccak256(abi.encodePacked(co)) == keccak256(abi.encodePacked(Util.uInt2Str(uint256(merkleProofIndexAndClearnaceOrder[1])))), "CLEARANCE_ORDER_ERROR");
        if (!Util.checkSliceIsRootHash(_slice, uint256(merkleProofIndexAndClearnaceOrder[0]), getRootHash(uint256(merkleProofIndexAndClearnaceOrder[1])))) {
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
            address payable addr = Util.splitAddr(indexValue);
            addr.transfer(0.01 ether);
            emit Transfer(addr, 0.01 ether, address(this).balance);
            return true;
        }

    }
}
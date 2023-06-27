// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

library Models {

    struct ClearanceRecord {
        uint256 clearanceOrder;
        bytes32 rootHash;
        uint256 createTime;
        bytes32 chainHash;
        string description;
    }

    enum ObjectionStatus {
        OK,
        NOT_FINISH,
        ROOT_HASH_NOT_MATCH_ERROR,
        PBPAIR_LIST_ERROR,
        RECEIPT_MISS_ERROR,
        RECEIPT_DUPLICATE_ERROR,
        RECEIPT_HASH_VALUE_DOES_NOT_MACTH_ERROR
    }

    struct ObjectionRecord {
        address messageSender;
        bytes32 receiptHash;
        string indexValue;
        string clearanceOrder;
        ObjectionStatus objectionStatus;
    }

}
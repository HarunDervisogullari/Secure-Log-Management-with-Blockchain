// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract LogNotary {
    struct LogRecord {
        string logId;
        string sourceId;
        string logHash;
        string ipfsCid;
        uint256 timestamp;
        bool exists;
    }

    mapping(string => LogRecord) private logs;
    event LogNotarized(string indexed logId, string sourceId, string logHash, string ipfsCid, uint256 timestamp);

    function recordLog(
        string memory _logId,
        string memory _sourceId,
        string memory _logHash,
        string memory _ipfsCid
    ) public {
        require(!logs[_logId].exists, "Error: Log ID already exists. History cannot be rewritten.");

        logs[_logId] = LogRecord({
            logId: _logId,
            sourceId: _sourceId,
            logHash: _logHash,
            ipfsCid: _ipfsCid,
            timestamp: block.timestamp,
            exists: true
        });

        emit LogNotarized(_logId, _sourceId, _logHash, _ipfsCid, block.timestamp);
    }

    function getLog(string memory _logId) public view returns (
        string memory sourceId,
        string memory logHash,
        string memory ipfsCid,
        uint256 timestamp
    ) {
        require(logs[_logId].exists, "Error: Log not found.");
        LogRecord memory record = logs[_logId];
        return (record.sourceId, record.logHash, record.ipfsCid, record.timestamp);
    }
}
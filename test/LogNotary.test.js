const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("LogNotary Smart Contract Tests", function () {
  let logNotary;
  let owner;

  // This runs before every test to reset the environment
  beforeEach(async function () {
    // Get the signers (simulated accounts)
    [owner] = await ethers.getSigners();

    // Deploy the contract anew for each test
    const LogNotaryFactory = await ethers.getContractFactory("LogNotary");
    logNotary = await LogNotaryFactory.deploy();
    
    // In Hardhat v2 (Ethers v6), we wait for deployment like this:
    await logNotary.waitForDeployment();
  });

  it("Should verify that a log can be recorded and retrieved accurately", async function () {
    const logId = "uuid-1234-5678";
    const sourceId = "192.168.1.50";
    const logHash = "abc123hash...";
    const ipfsCid = "QmHashOfEncryptedFile...";

    // 1. Record the log on the blockchain
    const tx = await logNotary.recordLog(logId, sourceId, logHash, ipfsCid);
    await tx.wait(); // Wait for the transaction to be mined

    // 2. Retrieve the log from the blockchain
    const result = await logNotary.getLog(logId);

    // 3. Assertions (Check if data matches)
    expect(result[0]).to.equal(sourceId); // Check Source ID
    expect(result[1]).to.equal(logHash);  // Check Log Hash (Integrity Proof)
    expect(result[2]).to.equal(ipfsCid);  // Check IPFS CID
    
    // Check if timestamp is valid (greater than 0)
    expect(result[3]).to.be.gt(0); 
    
    console.log("\t✅ Test 1 Passed: Log recorded and verified successfully.");
  });

  it("Should prevent overwriting an existing log (Immutability Check)", async function () {
    const logId = "unique-log-id-001";
    
    // First recording
    await logNotary.recordLog(logId, "SourceA", "Hash1", "CID1");

    // Attempt to record AGAIN with the SAME ID but different data
    // This MUST fail for the system to be secure
    await expect(
      logNotary.recordLog(logId, "SourceB", "FakeHash", "FakeCID")
    ).to.be.revertedWith("Error: Log ID already exists. History cannot be rewritten.");

    console.log("\t✅ Test 2 Passed: System successfully blocked an overwrite attempt.");
  });
});
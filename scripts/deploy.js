const hre = require("hardhat");

async function main() {
  // Kontrat fabrikasını çağır
  const LogNotary = await hre.ethers.getContractFactory("LogNotary");
  
  // Kontratı deploy et
  const logNotary = await LogNotary.deploy();

  // İşlemin bitmesini bekle
  await logNotary.waitForDeployment();

  // Adresi yazdır
  console.log("LogNotary deployed to:", await logNotary.getAddress());
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
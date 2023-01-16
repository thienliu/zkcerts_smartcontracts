import "@typechain/hardhat";
import "@nomiclabs/hardhat-ethers";
import "@nomiclabs/hardhat-waffle";
import "hardhat-gas-reporter";

 
export default {
  solidity: "0.8.8",
  mocha: {
    timeout: 200000
  }
};

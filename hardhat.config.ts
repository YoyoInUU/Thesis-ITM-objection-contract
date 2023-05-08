import "hardhat-deploy";

import "@nomiclabs/hardhat-solhint";
import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
  solidity: "0.8.7",
  networks: {},
  etherscan: {},
  namedAccounts: {
    deployer: {
      default: 0,
    },
    user: { default: 0 },
  },
};

export default config;

import { HardhatUserConfig } from "hardhat/types";
import "@nomicfoundation/hardhat-toolbox";
import "hardhat-deploy";
import "dotenv/config";
import "./tasks/curator-guard";

const localhost = process.env.FORK_NODE_URL || "http://localhost:8545";
const ethereumNodeUrl = process.env.ETHEREUM_NODE_URL || "";

// CuratorGuard sits close to the EIP-170 limit: it and its timelock deploy at 10 runs on the legacy pipeline
// (the vendored Safe test sources are not via-IR compatible), the same settings as foundry.toml, so the tested
// bytecode is the deployed one (docs/curator-guard.md section 13; scripts/check-contract-sizes.sh enforces the
// 96% gate). cancun: the guard needs EIP-1153 transient storage.
const solidity = {
  version: "0.8.25",
  settings: { evmVersion: "cancun", viaIR: false, optimizer: { enabled: true, runs: 10 } },
};

function getFork() {
  const nodeUrl = process.env.FORK_NODE_URL;
  return nodeUrl
    ? {
        initialBaseFeePerGas: 0,
        forking: {
          url: nodeUrl,
          blockNumber: process.env.FORK_BLOCK_NUMBER ? parseInt(process.env.FORK_BLOCK_NUMBER) : undefined,
        },
        chainId: 31337,
        deploy: ["deploy/ethereum"],
      } // eslint-disable-next-line @typescript-eslint/no-explicit-any
    : ({} as any);
}

let accounts;
if (process.env.MNEMONIC) accounts = { mnemonic: process.env.MNEMONIC };
if (process.env.PRIVATE_KEY) accounts = [process.env.PRIVATE_KEY];

const config: HardhatUserConfig = {
  defaultNetwork: "hardhat",
  networks: {
    hardhat: getFork(),
    localhost: {
      url: localhost,
      chainId: 31337,
      saveDeployments: true,
      autoImpersonate: true,
      deploy: ["deploy/ethereum"],
    },
    ethereum: { url: ethereumNodeUrl, chainId: 1, accounts, deploy: ["deploy/ethereum"] },
  },
  sourcify: { enabled: false },
  etherscan: { enabled: true, apiKey: process.env.ETHERSCAN_API_KEY },
  namedAccounts: { deployer: process.env.DEPLOYER || 0 },
  solidity: { compilers: [solidity] },
  mocha: { timeout: 400000 },
};

export default config;

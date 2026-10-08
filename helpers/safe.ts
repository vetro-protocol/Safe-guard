import fs from "fs";
import { HardhatRuntimeEnvironment, HttpNetworkConfig } from "hardhat/types";
import chalk from "chalk";
import SafeApiKit from "@safe-global/api-kit";
import Safe from "@safe-global/protocol-kit";
import { MetaTransactionData, OperationType } from "@safe-global/types-kit";
import { Contract, Wallet } from "ethers";

export const SAFE_BATCH_TXS_FILE = "safe.batch.tmp.json";

// Type returned by `hardhat-deploy`'s `catchUnknownSigner` function
type SafeBatchTx = {
  from: string;
  to?: string | undefined;
  value?: string | undefined;
  data?: string | undefined;
};

// `from` is preserved on the saved entry so the fork dry-run can impersonate the right caller
// per tx
type SavedTx = MetaTransactionData & { from?: string };

const { log } = console;

const getSafeSignerPrivateKey = (): string => {
  if (process.env.DEPLOYER_PRIVATE_KEY) {
    return process.env.DEPLOYER_PRIVATE_KEY;
  }

  if (process.env.MNEMONIC) {
    return Wallet.fromPhrase(process.env.MNEMONIC).privateKey;
  }

  throw Error("Missing signer credentials. Set DEPLOYER_PRIVATE_KEY or MNEMONIC.");
};

// `from` must be a contract. Lazy-import `hre` — a top-level import here crashes config
// load with HH9 once this module is reached via the `tasks/` → `helpers/debt-ratio` chain.
const assertFromIsContract = async (from: string): Promise<void> => {
  const { default: hre } = await import("hardhat");
  const code = await hre.ethers.provider.getCode(from);
  if (code === "0x") {
    throw new Error(`Queued tx \`from\` ${from} is an EOA, not a Safe contract — cannot dispatch via Safe batch.`);
  }
};

export const saveForSafeBatchExecution = async (rawTx: SafeBatchTx): Promise<void> => {
  await assertFromIsContract(rawTx.from);

  if (!fs.existsSync(SAFE_BATCH_TXS_FILE)) {
    fs.closeSync(fs.openSync(SAFE_BATCH_TXS_FILE, "w"));
  }

  const file = fs.readFileSync(SAFE_BATCH_TXS_FILE);

  const tx = prepareTx(rawTx);

  if (file.length == 0) {
    fs.writeFileSync(SAFE_BATCH_TXS_FILE, JSON.stringify([tx]));
  } else {
    const current = JSON.parse(file.toString()) as SavedTx[];

    const alreadyStored = current.find((i: SavedTx) => i.to == tx.to && i.data == tx.data && i.value == tx.value);

    if (alreadyStored) {
      log(chalk.blue(`This Safe transaction is already saved in '${SAFE_BATCH_TXS_FILE}'.`));
      return;
    }

    const json = [...current, tx];
    fs.writeFileSync(SAFE_BATCH_TXS_FILE, JSON.stringify(json));
  }

  log(chalk.blue(`Safe transaction saved in '${SAFE_BATCH_TXS_FILE}'.`));
};

export const executeBatchUsingSafe = async (hre: HardhatRuntimeEnvironment): Promise<void> => {
  if (!fs.existsSync(SAFE_BATCH_TXS_FILE)) {
    return;
  }

  const file = fs.readFileSync(SAFE_BATCH_TXS_FILE);

  const transactions: SavedTx[] = JSON.parse(file.toString());

  log(chalk.blue("Proposing Safe batch transaction..."));
  await proposeSafeTransaction(hre, transactions);

  fs.unlinkSync(SAFE_BATCH_TXS_FILE);
};

// Parse `hardhat-deploy` tx to `Safe` tx
const prepareTx = ({ from, to, data, value }: SafeBatchTx): SavedTx => {
  if (!to || !data) {
    throw Error("The `to` and `data` args can not be null");
  }

  return { to, data, value: value || "0", ...(from ? { from } : {}) };
};

// Group queued txs by required signer. Each tx's `from` is the address that must call it;
// one batch per signer so each lands at the right Safe. Every save site populates `from`,
// so a missing value here means tampering or a legacy file — refuse rather than guess.
const groupBySafe = (txs: SavedTx[]): Map<string, SavedTx[]> => {
  const groups = new Map<string, SavedTx[]>();
  for (const tx of txs) {
    if (!tx.from) throw new Error(`Queued tx missing required \`from\` (to=${tx.to}, data=${tx.data?.slice(0, 10)}…)`);
    const list = groups.get(tx.from) ?? [];
    list.push(tx);
    groups.set(tx.from, list);
  }
  return groups;
};

/// A fork / local dev node answers `hardhat_metadata` (hardhat) or `anvil_nodeInfo` (anvil); a real
/// RPC answers neither. Such a node is always impersonated, whatever the network is called: a rehearsal
/// on a fork network must never put a proposal into the PRODUCTION Safe queue signed by the key in
/// .env (docs/curator-guard.md section 13.2, R6C-13).
const isDevNode = async (hre: HardhatRuntimeEnvironment): Promise<boolean> => {
  for (const method of ["hardhat_metadata", "anvil_nodeInfo"]) {
    try {
      await hre.network.provider.send(method, []);
      return true;
    } catch {
      /* not that kind of node */
    }
  }
  return false;
};

const proposeSafeTransaction = async (hre: HardhatRuntimeEnvironment, txs: SavedTx[]) => {
  const groups = groupBySafe(txs);

  if (["hardhat", "localhost"].includes(hre.network.name) || (await isDevNode(hre))) {
    // Lazy-import — `account-helpers` pulls `hardhat` at top level which would HH9 the
    // config-load path that reaches this module via the `update-debt-ratio` task.
    const { impersonateAccount } = await import("./account-helpers");
    for (const [safe, group] of groups) {
      const w = await impersonateAccount(safe);
      for (const { to, data } of group) {
        await w.sendTransaction({ to, data });
      }
    }
    log(chalk.blue(`Test deployment: ${groups.size} impersonated Safe group(s) executed.`));
    return;
  }

  for (const [safe, group] of groups) {
    await proposeOneSafeBatch(hre, safe, group);
  }
};

const proposeOneSafeBatch = async (
  hre: HardhatRuntimeEnvironment,
  safeAddress: string,
  group: SavedTx[],
): Promise<void> => {
  const chainId = BigInt(await hre.getChainId());
  const { deployer: delegateAddress } = await hre.getNamedAccounts();
  const chainName = (await hre.ethers.provider.getNetwork()).name;

  const config = <HttpNetworkConfig>hre.config.networks[chainName];
  const provider = config.url;

  // The proposal is signed by DEPLOYER_PRIVATE_KEY / MNEMONIC and attributed to the named `deployer`
  // (DEPLOYER / PRIVATE_KEY): they must be one key, or the Safe service rejects the proposal after the
  // fact with a message that names neither.
  const signerKey = getSafeSignerPrivateKey();
  const signerAddress = new Wallet(signerKey).address;
  if (signerAddress.toLowerCase() !== delegateAddress.toLowerCase()) {
    throw Error(
      `the Safe proposal signer ${signerAddress} (DEPLOYER_PRIVATE_KEY / MNEMONIC) is not the named deployer ${delegateAddress}`,
    );
  }

  const apiKit = new SafeApiKit({ chainId, apiKey: process.env.SAFE_API_KEY });

  // protocol-kit knows a fixed list of Safe releases (6.1.2: v1.0.0 to v1.4.1) and throws a bare "Invalid Safe
  // version" for any other, Safe v1.5.0 included (Safe{Wallet}'s default for new Safes since September 2026):
  // name the Safe, its version and the fix instead (review G11f).
  let protocolKit: Safe;
  try {
    protocolKit = await Safe.init({
      provider: provider,
      signer: signerKey,
      safeAddress,
    });
  } catch (e) {
    if (!String((e as Error).message).includes("Invalid Safe version")) throw e;
    const version = await new Contract(
      safeAddress,
      ["function VERSION() view returns (string)"],
      hre.ethers.provider,
    ).VERSION();
    throw Error(
      `Safe ${safeAddress} runs Safe v${version}, which this @safe-global/protocol-kit does not know: upgrade ` +
        `protocol-kit to a release that lists v${version} (grep '"${version}"' node_modules/@safe-global/protocol-kit/dist/cjs/src/index.cjs), ` +
        `or propose this batch from Safe{Wallet}'s Transaction Builder`,
    );
  }

  // Strip the saved `from` — Safe SDK only consumes (to, value, data, operation).
  const safeTransactionData: MetaTransactionData[] = group.map(({ to, value, data }) => ({
    to,
    value,
    data,
    operation: OperationType.Call,
  }));

  const safeTransaction = await protocolKit.createTransaction({
    transactions: safeTransactionData,
    onlyCalls: true,
    options: { nonce: Number(await apiKit.getNextNonce(safeAddress)) },
  });

  const safeTxHash = await protocolKit.getTransactionHash(safeTransaction);
  const signature = await protocolKit.signHash(safeTxHash);

  await apiKit.proposeTransaction({
    safeAddress,
    safeTransactionData: safeTransaction.data,
    safeTxHash,
    senderAddress: delegateAddress,
    senderSignature: signature.data,
  });

  log(chalk.blue(`Batch tx '${safeTxHash}' proposed to Safe ${safeAddress} (${group.length} call(s)).`));
  log(chalk.blue("Wait for tx to confirm (at least 2 confirmations is recommended)."));
  log(chalk.blue("After confirmation, you must run the deployment again."));
  log(chalk.blue("That way the `hardhat-deploy` will be able to catch the changes and update `deployments/` files."));
};

import hre from "hardhat";

// Ethereum addresses used by the CuratorGuard deploy script, tasks and fork rehearsal.
const A = {
  ethereum: {
    USDC: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    USDT: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
    WBTC: "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599",
    cbBTC: "0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf",
    hemiBTC: "0x06ea695B91700071B161A434fED42D1DcbAD9f00",
    Lagoon: {
      vault: {
        Vetro_USDC: "0x131CcfDFfeD712885aAc31445d351E6b62656679",
        Vetro_USDT: "0xE7FaE53e32B09028db4Ca8Ff7E4fF0574367eDba",
        Vetro_WBTC: "0x1a9b5c9845c2685923215779c6Ec288bD5090e90",
        Vetro_cbBTC: "0x110B1F3cD409Ef5A7b354AA1667c19998E1b6340",
        Vetro_hemiBTC: "0x26A6179247420B6e8036DBdeF48fD74d1E57fdc3",
      },
    },
    Vetro: {
      feeCollector: "0x6649Ddb5c7e52348b73c8bBdD2A1cbA630b7AaEA",
      // Safe v1.4.1 (2-of-4) that is both `safe()` (custody) and `owner()` of every Lagoon.vault.Vetro_*
      // above. `CuratorGuard` policies are keyed by this address (policies/curator-guard/).
      lagoonCuratorSafe: "0x1b534a8543212F5957168D83311A41E0Ea1cfe48",
      // CuratorGuard v2 roles (docs/curator-guard.md sections 4 and 12, IMPROVEMENTS_V2.md item 1).
      // `curatorGuardProposers`: the Safes that PROPOSE widenings to the CuratorGuardTimelock, which is
      // the guard's DEFAULT_ADMIN. Proposed: the Vetro governance Safe (v1.4.1, 3-of-6) that is
      // `governor()` of every Vetro yield vault and of the Lagoon_Vetro_* strategies (same address as
      // `feeCollector`). CAVEAT (verified on-chain 2026-10-04): three of its six owners are also owners
      // of `lagoonCuratorSafe`. The deploy script REFUSES a proposer, canceller or council that shares a
      // signer with the curator Safe (CURATOR_GUARD_ALLOW_KEY_OVERLAP=1 downgrades it to a warning on
      // fork rehearsals only), so a dedicated governance Safe without curator keys must replace this
      // before mainnet. List two proposers so a single lost Safe cannot strand the guard; a proposer
      // that is not the canceller holds PROPOSER_ROLE only and is removable if compromised.
      curatorGuardProposers: ["0x6649Ddb5c7e52348b73c8bBdD2A1cbA630b7AaEA"],
      // `curatorGuardCouncil`: fast lane with NO curator keys (lift lockdowns, approvals <= 7 days,
      // Bypass <= 7 days, guardians). REQUIRED on real networks (the deploy script refuses an empty
      // council unless CURATOR_GUARD_ALLOW_NO_COUNCIL=1). It holds NO timelock role: a council that could
      // cancel or propose would veto or schedule its own removal (docs section 13.2, V2-54 / V2-63).
      curatorGuardCouncil: "",
      // `curatorGuardCancellers`: EXACTLY ONE dedicated veto Safe that may cancel a queued operation on
      // the timelock and proposes nothing (the contract refuses a canceller that is also a proposer:
      // a compromised canceller-proposer would be an unvetoed takeover, a compromised veto-only Safe at
      // worst a deadlock; V2-63 / V2-74). Ideally a 2-of-3 Safe of three distinct governance parties,
      // without curator keys. A second canceller would be a second permanent veto. Never a hot key,
      // never the council. EMPTY until Vetro creates it: the deploy script refuses an empty list on
      // real networks and the fork rehearsal uses a stand-in. Guardian bots live in the policy files
      // (per Safe) or hold GUARDIAN_ROLE on the guard.
      curatorGuardCancellers: [] as string[],
    },
    Safe: {
      // safe-deployments canonical addresses. MultiSendCallOnly is the ONLY delegatecall target a
      // CuratorGuard policy may register; never register plain MultiSend (v1.3.0 0xA238…7761,
      // v1.4.1 0x3886…B526), it permits nested delegatecalls.
      multiSendCallOnly_v1_3_0: "0x40A2aCCbd92BCA938b02010E17A5b8929b49130D",
      multiSendCallOnly_v1_4_1: "0x9641d764fc13c8B624c04430C7356C1C7C8102e2",
      multiSendCallOnly_v1_5_0: "0xA83c336B20401Af773B6219BA5027174338D1836",
    },
  },
};

const chains: Record<number, string> = {
  1: "ethereum",
  31337: "ethereum",
};

const getChain = (): string => {
  const { chainId } = hre.network.config;
  const chain = chains[chainId!];
  if (!chain) throw Error(`No address setup for chainId ${chainId}`);
  return chain;
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const Address = (A as { [key: string]: any })[getChain()];

export default A;

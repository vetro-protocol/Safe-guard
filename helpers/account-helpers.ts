import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { parseEther } from "ethers";
import { ethers } from "hardhat";
import { impersonateAccount as impersonate, setBalance } from "@nomicfoundation/hardhat-network-helpers";

export const impersonateAccount = async (address: string): Promise<SignerWithAddress> => {
  await impersonate(address);
  await setBalance(address, parseEther("1000000"));
  return await ethers.getSigner(address);
};

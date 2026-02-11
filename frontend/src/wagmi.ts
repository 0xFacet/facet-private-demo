import { connectorsForWallets } from '@rainbow-me/rainbowkit'
import { metaMaskWallet, walletConnectWallet, coinbaseWallet, rabbyWallet, rainbowWallet, okxWallet } from '@rainbow-me/rainbowkit/wallets'
import { createConfig, http } from 'wagmi'
import { sepolia } from 'wagmi/chains'
import { defineChain } from 'viem'

const ADAPTER_URL = import.meta.env.VITE_ADAPTER_URL || 'http://localhost:8546'
const projectId = import.meta.env.VITE_WALLETCONNECT_PROJECT_ID || 'PLACEHOLDER'

export const facetPrivate = defineChain({
  id: 13371337,
  name: 'Facet Private',
  nativeCurrency: { name: 'ETH', symbol: 'ETH', decimals: 18 },
  rpcUrls: { default: { http: [ADAPTER_URL] } },
})

const connectors = connectorsForWallets([
  {
    groupName: 'Installed',
    wallets: [metaMaskWallet, coinbaseWallet],
  },
  {
    groupName: 'Other',
    wallets: [rabbyWallet, rainbowWallet, okxWallet, walletConnectWallet],
  },
], { appName: 'Facet Private', projectId })

export const config = createConfig({
  connectors,
  chains: [sepolia, facetPrivate],
  transports: {
    [sepolia.id]: http(),
    [facetPrivate.id]: http(ADAPTER_URL),
  },
})

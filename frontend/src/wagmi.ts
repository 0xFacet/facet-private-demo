import { getDefaultConfig } from '@rainbow-me/rainbowkit'
import { http } from 'wagmi'
import { sepolia } from 'wagmi/chains'
import { defineChain } from 'viem'

const ADAPTER_URL = import.meta.env.VITE_ADAPTER_URL || 'http://localhost:8546'

export const facetPrivate = defineChain({
  id: 13371337,
  name: 'Facet Private',
  nativeCurrency: { name: 'ETH', symbol: 'ETH', decimals: 18 },
  rpcUrls: { default: { http: [ADAPTER_URL] } },
})

export const config = getDefaultConfig({
  appName: 'Facet Private',
  projectId: import.meta.env.VITE_WALLETCONNECT_PROJECT_ID || 'PLACEHOLDER',
  chains: [sepolia, facetPrivate],
  transports: {
    [sepolia.id]: http(),
    [facetPrivate.id]: http(ADAPTER_URL),
  },
})

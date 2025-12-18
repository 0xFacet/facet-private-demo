import { useState, useEffect, useCallback } from 'react'
import { encodeFunctionData, parseEther as viemParseEther, formatEther as viemFormatEther } from 'viem'

// Configuration
const ADAPTER_URL = 'http://localhost:8546'
const WITHDRAW_SENTINEL = '0x0000000000000000000000000000000000000001'
const SEPOLIA_CHAIN_ID = '0xaa36a7' // 11155111
const VIRTUAL_CHAIN_ID = '0xcc07c9' // 13371337

// Contract address - must match deployed contract
const PRIVACY_POOL_ADDRESS = import.meta.env.VITE_PRIVACY_POOL_ADDRESS || '0x' // Set via env

// BN254 field size for randomness
const FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

// Contract ABI for deposit
const PRIVACY_POOL_ABI = [{
  name: 'deposit',
  type: 'function',
  stateMutability: 'payable',
  inputs: [
    { name: 'noteOwner', type: 'uint256' },
    { name: 'randomness', type: 'uint256' },
    { name: 'encryptedNote', type: 'bytes' },
  ],
  outputs: [],
}] as const

interface Note {
  amount: string
  commitment: string
  leafIndex: number
  spent: boolean
}

declare global {
  interface Window {
    ethereum?: {
      request: (args: { method: string; params?: unknown[] }) => Promise<unknown>
      on: (event: string, callback: (...args: unknown[]) => void) => void
    }
  }
}

// RPC helper for adapter
async function rpc(method: string, params: unknown[] = []): Promise<unknown> {
  const res = await fetch(ADAPTER_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', method, params, id: Date.now() }),
  })
  const json = await res.json()
  if (json.error) throw new Error(json.error.message)
  return json.result
}

// Format helpers
function parseEther(eth: string): bigint {
  return viemParseEther(eth)
}

function formatEther(wei: bigint): string {
  const full = viemFormatEther(wei)
  const num = parseFloat(full)
  return num.toLocaleString('en-US', { maximumFractionDigits: 4 })
}

// Generate random bigint for note randomness
function randomBigInt(): bigint {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  let hex = '0x'
  for (const b of bytes) hex += b.toString(16).padStart(2, '0')
  return BigInt(hex) % FIELD_SIZE
}

// Switch to a specific network
async function switchToNetwork(chainId: string, addIfMissing = false) {
  try {
    await window.ethereum!.request({
      method: 'wallet_switchEthereumChain',
      params: [{ chainId }],
    })
  } catch (err: unknown) {
    if ((err as { code: number }).code === 4902 && addIfMissing) {
      await window.ethereum!.request({
        method: 'wallet_addEthereumChain',
        params: [{
          chainId: VIRTUAL_CHAIN_ID,
          chainName: 'Facet Private (L2)',
          rpcUrls: [ADAPTER_URL],
          nativeCurrency: { name: 'ETH', symbol: 'ETH', decimals: 18 },
        }],
      })
    } else {
      throw err
    }
  }
}

function App() {
  const [account, setAccount] = useState<string | null>(null)
  const [registered, setRegistered] = useState(false)
  const [balance, setBalance] = useState<string>('--')
  const [l1Balance, setL1Balance] = useState<string>('--')
  const [notes, setNotes] = useState<Note[]>([])
  const [status, setStatus] = useState<{ message: string; type: 'success' | 'error' | 'pending' } | null>(null)
  const [loading, setLoading] = useState<string | null>(null)

  // Form state
  const [depositAmount, setDepositAmount] = useState('')
  const [transferTo, setTransferTo] = useState('')
  const [transferAmount, setTransferAmount] = useState('')
  const [withdrawAmount, setWithdrawAmount] = useState('')

  const showStatus = useCallback((message: string, type: 'success' | 'error' | 'pending' = 'success') => {
    setStatus({ message, type })
    if (type === 'success') {
      setTimeout(() => setStatus(null), 5000)
      setLoading(null)
    }
  }, [])

  const updateBalance = useCallback(async () => {
    if (!account) return
    try {
      const [shielded, l1] = await Promise.all([
        rpc('eth_getBalance', [account, 'latest']) as Promise<string>,
        rpc('privacy_getL1Balance', [account]) as Promise<string>,
      ])
      setBalance(formatEther(BigInt(shielded)))
      setL1Balance(formatEther(BigInt(l1)))
    } catch (e) {
      console.error('Balance error:', e)
    }
  }, [account])

  const updateNotes = useCallback(async () => {
    if (!account) return
    try {
      const noteList = await rpc('privacy_getNotes', [account]) as Note[]
      setNotes(noteList)
    } catch (e) {
      console.error('Notes error:', e)
    }
  }, [account])

  // Update data when account/registered changes
  useEffect(() => {
    if (account && registered) {
      updateBalance()
      updateNotes()
    }
  }, [account, registered, updateBalance, updateNotes])

  // Connect wallet
  const connect = async () => {
    try {
      if (!window.ethereum) {
        throw new Error('MetaMask not found. Please install MetaMask.')
      }

      const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' }) as string[]
      const addr = accounts[0]
      setAccount(addr)

      showStatus('Wallet connected! Please register your viewing key.')
    } catch (e) {
      showStatus((e as Error).message, 'error')
    }
  }

  // Register viewing key
  const register = async () => {
    try {
      if (!account) return
      setLoading('register')
      showStatus('Please sign the message in MetaMask...', 'pending')

      const message = `Register viewing key for Facet Private\nAddress: ${account}`
      const signature = await window.ethereum!.request({
        method: 'personal_sign',
        params: [message, account],
      }) as string

      await rpc('privacy_registerViewingKey', [account, signature])

      setRegistered(true)
      setLoading(null)
      showStatus('Viewing key registered! You can now deposit ETH.')
    } catch (e) {
      setLoading(null)
      showStatus((e as Error).message, 'error')
    }
  }

  // L1 Deposit - user signs directly on Sepolia
  const deposit = async () => {
    try {
      if (!depositAmount || parseFloat(depositAmount) <= 0) {
        throw new Error('Please enter a valid amount')
      }
      if (!PRIVACY_POOL_ADDRESS || PRIVACY_POOL_ADDRESS === '0x') {
        throw new Error('Privacy pool address not configured')
      }

      setLoading('deposit')

      // Ensure we're on Sepolia
      showStatus('Switching to Sepolia...', 'pending')
      await switchToNetwork(SEPOLIA_CHAIN_ID)

      const amount = parseEther(depositAmount)
      const owner = BigInt(account!)
      const randomness = randomBigInt()

      showStatus('Encrypting note data...', 'pending')

      // Get encrypted note from adapter
      const encryptedNote = await rpc('privacy_encryptNoteData', [
        account,
        {
          owner: '0x' + owner.toString(16),
          amount: '0x' + amount.toString(16),
          randomness: '0x' + randomness.toString(16),
        },
      ]) as `0x${string}`

      // Encode the deposit call
      const data = encodeFunctionData({
        abi: PRIVACY_POOL_ABI,
        functionName: 'deposit',
        args: [owner, randomness, encryptedNote],
      })

      showStatus('Confirm deposit in MetaMask...', 'pending')

      // User signs tx directly on Sepolia
      const txHash = await window.ethereum!.request({
        method: 'eth_sendTransaction',
        params: [{
          from: account,
          to: PRIVACY_POOL_ADDRESS,
          value: '0x' + amount.toString(16),
          data,
        }],
      }) as string

      showStatus('Waiting for deposit confirmation...', 'pending')

      // Tell adapter to watch for this deposit and sync
      await rpc('privacy_watchForDeposit', [account, txHash])

      await Promise.all([updateBalance(), updateNotes()])
      setDepositAmount('')
      showStatus('Deposit complete! Your shielded balance is updated.')
    } catch (e) {
      setLoading(null)
      showStatus((e as Error).message, 'error')
    }
  }

  // Transfer (on L2)
  const transfer = async () => {
    try {
      if (!transferTo || !transferTo.startsWith('0x')) {
        throw new Error('Please enter a valid recipient address')
      }
      if (!transferAmount || parseFloat(transferAmount) <= 0) {
        throw new Error('Please enter a valid amount')
      }

      setLoading('transfer')

      // Check if recipient is registered before attempting transfer
      showStatus('Checking recipient registration...', 'pending')
      const recipientKey = await rpc('privacy_getEncryptionKey', [transferTo])
      if (!recipientKey) {
        throw new Error(`Recipient ${transferTo.slice(0, 10)}... is not registered. They must register a viewing key first.`)
      }

      // Ensure we're on virtual chain
      showStatus('Switching to L2...', 'pending')
      await switchToNetwork(VIRTUAL_CHAIN_ID, true)

      const weiAmount = '0x' + parseEther(transferAmount).toString(16)
      showStatus('Confirm transfer in MetaMask...', 'pending')

      const txHash = await window.ethereum!.request({
        method: 'eth_sendTransaction',
        params: [{ from: account, to: transferTo, value: weiAmount }],
      }) as string

      showStatus('Generating ZK proof (this takes ~30 seconds)...', 'pending')

      let receipt = null
      while (!receipt) {
        await new Promise(r => setTimeout(r, 3000))
        receipt = await rpc('eth_getTransactionReceipt', [txHash])
      }

      await Promise.all([updateBalance(), updateNotes()])
      setTransferTo('')
      setTransferAmount('')
      showStatus('Transfer complete! Proof verified on Sepolia.')
    } catch (e) {
      setLoading(null)
      showStatus((e as Error).message, 'error')
    }
  }

  // Withdraw (on L2)
  const withdraw = async () => {
    try {
      if (!withdrawAmount || parseFloat(withdrawAmount) <= 0) {
        throw new Error('Please enter a valid amount')
      }

      setLoading('withdraw')

      // Ensure we're on virtual chain
      showStatus('Switching to L2...', 'pending')
      await switchToNetwork(VIRTUAL_CHAIN_ID, true)

      const weiAmount = '0x' + parseEther(withdrawAmount).toString(16)
      showStatus('Confirm withdrawal in MetaMask...', 'pending')

      const txHash = await window.ethereum!.request({
        method: 'eth_sendTransaction',
        params: [{ from: account, to: WITHDRAW_SENTINEL, value: weiAmount }],
      }) as string

      showStatus('Generating ZK proof (this takes ~30 seconds)...', 'pending')

      let receipt = null
      while (!receipt) {
        await new Promise(r => setTimeout(r, 3000))
        receipt = await rpc('eth_getTransactionReceipt', [txHash])
      }

      await Promise.all([updateBalance(), updateNotes()])
      setWithdrawAmount('')
      showStatus('Withdrawal complete! ETH sent to your wallet.')
    } catch (e) {
      setLoading(null)
      showStatus((e as Error).message, 'error')
    }
  }

  const unspentNotes = notes.filter(n => !n.spent)

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-md mx-auto space-y-4">
        {/* Header */}
        <div className="text-center mb-6">
          <h1 className="text-3xl font-bold text-cyan-400">Facet Private</h1>
          <p className="text-slate-400 mt-1">Private ETH transactions with ZK proofs</p>
          {account && (
            <p className="text-slate-500 text-xs font-mono mt-2 break-all">{account}</p>
          )}
        </div>

        {/* Connect / Register */}
        {(!account || !registered) && (
          <div className="bg-slate-800 rounded-xl p-4">
            {!account ? (
              <button
                onClick={connect}
                disabled={!!loading}
                className="w-full bg-cyan-500 hover:bg-cyan-400 disabled:bg-slate-600 disabled:cursor-not-allowed text-slate-900 font-semibold py-3 px-6 rounded-lg transition"
              >
                Connect Wallet
              </button>
            ) : (
              <button
                onClick={register}
                disabled={!!loading}
                className="w-full bg-slate-700 hover:bg-slate-600 disabled:bg-slate-600 disabled:cursor-not-allowed text-cyan-400 disabled:text-slate-500 font-semibold py-3 px-6 rounded-lg transition"
              >
                {loading === 'register' ? 'Registering...' : 'Register Viewing Key'}
              </button>
            )}
          </div>
        )}

        {/* L1 Section */}
        {registered && (
          <div className="bg-slate-800 rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div className="text-emerald-400 font-semibold">L1 Sepolia</div>
              <div className="text-emerald-400 font-bold">{l1Balance} ETH</div>
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="Amount"
                value={depositAmount}
                onChange={(e) => setDepositAmount(e.target.value)}
                disabled={!!loading}
                className="flex-1 bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-slate-100 placeholder-slate-400 focus:outline-none focus:border-emerald-500 disabled:opacity-50"
              />
              <button
                onClick={deposit}
                disabled={!!loading}
                className="bg-emerald-500 hover:bg-emerald-400 disabled:bg-slate-600 disabled:cursor-not-allowed text-slate-900 disabled:text-slate-400 font-semibold py-2 px-4 rounded-lg transition whitespace-nowrap"
              >
                {loading === 'deposit' ? '...' : 'Deposit →'}
              </button>
            </div>
          </div>
        )}

        {/* L2 Section */}
        {registered && (
          <div className="bg-slate-800 rounded-xl p-4 space-y-4">
            <div className="flex items-center justify-between">
              <div className="text-cyan-400 font-semibold">L2 Shielded</div>
              <div className="text-cyan-400 font-bold">{balance} ETH</div>
            </div>

            {/* Transfer */}
            <div className="space-y-2">
              <div className="text-slate-400 text-sm">Private Transfer</div>
              <input
                type="text"
                placeholder="Recipient (0x...)"
                value={transferTo}
                onChange={(e) => setTransferTo(e.target.value)}
                disabled={!!loading}
                className="w-full bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-slate-100 placeholder-slate-400 focus:outline-none focus:border-cyan-500 disabled:opacity-50"
              />
              <div className="flex gap-2">
                <input
                  type="text"
                  placeholder="Amount"
                  value={transferAmount}
                  onChange={(e) => setTransferAmount(e.target.value)}
                  disabled={!!loading}
                  className="flex-1 bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-slate-100 placeholder-slate-400 focus:outline-none focus:border-cyan-500 disabled:opacity-50"
                />
                <button
                  onClick={transfer}
                  disabled={!!loading}
                  className="bg-cyan-500 hover:bg-cyan-400 disabled:bg-slate-600 disabled:cursor-not-allowed text-slate-900 disabled:text-slate-400 font-semibold py-2 px-4 rounded-lg transition whitespace-nowrap"
                >
                  {loading === 'transfer' ? '...' : 'Send'}
                </button>
              </div>
            </div>

            {/* Withdraw */}
            <div className="space-y-2 pt-2 border-t border-slate-700">
              <div className="text-slate-400 text-sm">Withdraw to L1</div>
              <div className="flex gap-2">
                <input
                  type="text"
                  placeholder="Amount"
                  value={withdrawAmount}
                  onChange={(e) => setWithdrawAmount(e.target.value)}
                  disabled={!!loading}
                  className="flex-1 bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-slate-100 placeholder-slate-400 focus:outline-none focus:border-cyan-500 disabled:opacity-50"
                />
                <button
                  onClick={withdraw}
                  disabled={!!loading}
                  className="bg-cyan-500 hover:bg-cyan-400 disabled:bg-slate-600 disabled:cursor-not-allowed text-slate-900 disabled:text-slate-400 font-semibold py-2 px-4 rounded-lg transition whitespace-nowrap"
                >
                  {loading === 'withdraw' ? '...' : 'Withdraw'}
                </button>
              </div>
            </div>

            {/* Notes */}
            {unspentNotes.length > 0 && (
              <div className="pt-2 border-t border-slate-700">
                <div className="text-slate-400 text-sm mb-2">Notes ({unspentNotes.length})</div>
                <div className="flex flex-wrap gap-2">
                  {unspentNotes.map((note, i) => (
                    <div key={i} className="bg-slate-700 rounded px-2 py-1 text-sm text-cyan-400">
                      {formatEther(BigInt(note.amount))} ETH
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Status */}
        {status && (
          <div
            className={`rounded-lg p-4 text-sm flex items-center gap-3 ${
              status.type === 'success'
                ? 'bg-cyan-500/20 text-cyan-400'
                : status.type === 'error'
                ? 'bg-red-500/20 text-red-400'
                : 'bg-orange-500/20 text-orange-400'
            }`}
          >
            {status.type === 'pending' && (
              <svg className="animate-spin h-4 w-4 flex-shrink-0" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
              </svg>
            )}
            {status.message}
          </div>
        )}
      </div>
    </div>
  )
}

export default App

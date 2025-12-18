import { useState, useEffect, useCallback, useRef } from 'react'
import { encodeFunctionData, parseEther as viemParseEther, formatEther as viemFormatEther } from 'viem'

// Configuration
const ADAPTER_URL = import.meta.env.VITE_ADAPTER_URL || 'http://localhost:8546'
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

interface Transaction {
  type: 'deposit' | 'transfer' | 'transfer_in' | 'transfer_out' | 'transfer_self' | 'withdraw'
  virtualHash: string
  l1Hash: string
  amount: string
  recipient?: string
  timestamp: number
}

interface Status {
  message: string
  type: 'success' | 'error' | 'pending'
  txHash?: string
  section?: 'deposit' | 'transfer' | 'withdraw'
}

const ETHERSCAN_URL = 'https://sepolia.etherscan.io/tx/'

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
  return num.toLocaleString('en-US', { minimumFractionDigits: 5, maximumFractionDigits: 5 })
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

// Status display component
function StatusDisplay({ status, elapsedTime }: { status: Status | null; elapsedTime: number }) {
  if (!status) return null

  return (
    <div
      className={`rounded-lg p-3 text-sm flex items-center gap-3 ${
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
      <div className="flex-1">
        <div>{status.message}</div>
        {status.type === 'pending' && status.message.includes('proof') && (
          <div className="text-xs opacity-75 mt-1">
            {elapsedTime}s elapsed - proof generation takes ~60s on this demo server
          </div>
        )}
        {status.type === 'success' && status.txHash && (
          <a
            href={`${ETHERSCAN_URL}${status.txHash}`}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs underline hover:no-underline mt-1 inline-block"
          >
            View on Etherscan
          </a>
        )}
      </div>
    </div>
  )
}

function App() {
  const [account, setAccount] = useState<string | null>(null)
  const [registered, setRegistered] = useState(false)
  const [balance, setBalance] = useState<string>('--')
  const [l1Balance, setL1Balance] = useState<string>('--')
  const [notes, setNotes] = useState<Note[]>([])
  const [transactions, setTransactions] = useState<Transaction[]>([])
  const [status, setStatus] = useState<Status | null>(null)
  const [loading, setLoading] = useState<string | null>(null)
  const [proofStartTime, setProofStartTime] = useState<number | null>(null)
  const [elapsedTime, setElapsedTime] = useState(0)
  const [sessionLost, setSessionLost] = useState(false)

  // Form state with status clearing
  const [depositAmount, setDepositAmountRaw] = useState('')
  const [transferTo, setTransferToRaw] = useState('')
  const [transferAmount, setTransferAmountRaw] = useState('')
  const [withdrawAmount, setWithdrawAmountRaw] = useState('')

  // Wrapper setters that clear status when user starts typing
  const setDepositAmount = (v: string) => {
    setDepositAmountRaw(v)
    if (status?.section === 'deposit' && status?.type !== 'pending') setStatus(null)
  }
  const setTransferTo = (v: string) => {
    setTransferToRaw(v)
    if (status?.section === 'transfer' && status?.type !== 'pending') setStatus(null)
  }
  const setTransferAmount = (v: string) => {
    setTransferAmountRaw(v)
    if (status?.section === 'transfer' && status?.type !== 'pending') setStatus(null)
  }
  const setWithdrawAmount = (v: string) => {
    setWithdrawAmountRaw(v)
    if (status?.section === 'withdraw' && status?.type !== 'pending') setStatus(null)
  }

  // Track last successful tx hash for each section
  const lastTxHash = useRef<string | null>(null)

  // Timer for proof generation
  useEffect(() => {
    if (!proofStartTime) {
      setElapsedTime(0)
      return
    }
    const interval = setInterval(() => {
      setElapsedTime(Math.floor((Date.now() - proofStartTime) / 1000))
    }, 1000)
    return () => clearInterval(interval)
  }, [proofStartTime])

  const showStatus = useCallback((message: string, type: 'success' | 'error' | 'pending' = 'success', section?: 'deposit' | 'transfer' | 'withdraw', txHash?: string) => {
    setStatus({ message, type, section, txHash })
    if (type === 'success') {
      // Don't auto-dismiss - keep until form interaction
      setLoading(null)
      setProofStartTime(null)
    } else if (type === 'error') {
      setProofStartTime(null)
    }
  }, [])

  const checkSession = useCallback(async () => {
    if (!account) return true
    try {
      const hasSession = await rpc('privacy_hasSession', [account]) as boolean
      setSessionLost(!hasSession)
      return hasSession
    } catch (e) {
      console.error('Session check error:', e)
      return false
    }
  }, [account])

  const updateBalance = useCallback(async () => {
    if (!account) return
    try {
      // Check session first
      const hasSession = await checkSession()
      if (!hasSession) return

      const [shielded, l1] = await Promise.all([
        rpc('eth_getBalance', [account, 'latest']) as Promise<string>,
        rpc('privacy_getL1Balance', [account]) as Promise<string>,
      ])
      setBalance(formatEther(BigInt(shielded)))
      setL1Balance(formatEther(BigInt(l1)))
    } catch (e) {
      console.error('Balance error:', e)
    }
  }, [account, checkSession])

  const updateNotes = useCallback(async () => {
    if (!account) return
    try {
      const noteList = await rpc('privacy_getNotes', [account]) as Note[]
      setNotes(noteList)
    } catch (e) {
      console.error('Notes error:', e)
    }
  }, [account])

  const updateTransactions = useCallback(async () => {
    if (!account) return
    try {
      const txList = await rpc('privacy_getTransactions', [account]) as Transaction[]
      setTransactions(txList)
    } catch (e) {
      console.error('Transactions error:', e)
    }
  }, [account])

  const refreshAll = useCallback(async () => {
    if (!account) return
    try {
      setLoading('refresh')
      await rpc('privacy_refresh', [account])
      await Promise.all([updateBalance(), updateNotes(), updateTransactions()])
      setLoading(null)
    } catch (e) {
      console.error('Refresh error:', e)
      setLoading(null)
    }
  }, [account, updateBalance, updateNotes, updateTransactions])

  // Update data when account/registered changes
  useEffect(() => {
    if (account && registered) {
      updateBalance()
      updateNotes()
      updateTransactions()
    }
  }, [account, registered, updateBalance, updateNotes, updateTransactions])

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
      showStatus('Switching to Sepolia...', 'pending', 'deposit')
      await switchToNetwork(SEPOLIA_CHAIN_ID)

      const amount = parseEther(depositAmount)
      const owner = BigInt(account!)
      const randomness = randomBigInt()

      showStatus('Encrypting note data...', 'pending', 'deposit')

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

      showStatus('Confirm deposit in MetaMask...', 'pending', 'deposit')

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

      showStatus('Waiting for deposit confirmation...', 'pending', 'deposit')

      // Tell adapter to watch for this deposit and sync
      await rpc('privacy_watchForDeposit', [account, txHash])

      await Promise.all([updateBalance(), updateNotes(), updateTransactions()])
      setDepositAmount('')
      lastTxHash.current = txHash
      showStatus('Deposit complete!', 'success', 'deposit', txHash)
    } catch (e) {
      setLoading(null)
      showStatus((e as Error).message, 'error', 'deposit')
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
      showStatus('Checking recipient registration...', 'pending', 'transfer')
      const recipientKey = await rpc('privacy_getEncryptionKey', [transferTo])
      if (!recipientKey) {
        throw new Error(`Recipient ${transferTo.slice(0, 10)}... is not registered. They must register a viewing key first.`)
      }

      // Ensure we're on virtual chain
      showStatus('Switching to L2...', 'pending', 'transfer')
      await switchToNetwork(VIRTUAL_CHAIN_ID, true)

      const weiAmount = '0x' + parseEther(transferAmount).toString(16)
      // Start timing before MetaMask - the proof generation happens during the RPC call
      setProofStartTime(Date.now())
      showStatus('Confirm in MetaMask, then wait for proof generation...', 'pending', 'transfer')

      const txHash = await window.ethereum!.request({
        method: 'eth_sendTransaction',
        params: [{ from: account, to: transferTo, value: weiAmount }],
      }) as string

      showStatus('Submitting proof to L1...', 'pending', 'transfer')

      let receipt = null
      while (!receipt) {
        await new Promise(r => setTimeout(r, 3000))
        receipt = await rpc('eth_getTransactionReceipt', [txHash])
      }

      // Get the L1 tx hash from the receipt or transactions
      await Promise.all([updateBalance(), updateNotes(), updateTransactions()])
      setTransferTo('')
      setTransferAmount('')

      // Find the L1 hash from the latest transaction (last in array)
      const txList = await rpc('privacy_getTransactions', [account]) as Transaction[]
      const latestTransfer = txList.filter(t => t.type === 'transfer' || t.type === 'transfer_out').pop()
      const l1Hash = latestTransfer?.l1Hash

      showStatus('Transfer complete!', 'success', 'transfer', l1Hash)
    } catch (e) {
      setLoading(null)
      showStatus((e as Error).message, 'error', 'transfer')
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
      showStatus('Switching to L2...', 'pending', 'withdraw')
      await switchToNetwork(VIRTUAL_CHAIN_ID, true)

      const weiAmount = '0x' + parseEther(withdrawAmount).toString(16)
      // Start timing before MetaMask - the proof generation happens during the RPC call
      setProofStartTime(Date.now())
      showStatus('Confirm in MetaMask, then wait for proof generation...', 'pending', 'withdraw')

      const txHash = await window.ethereum!.request({
        method: 'eth_sendTransaction',
        params: [{ from: account, to: WITHDRAW_SENTINEL, value: weiAmount }],
      }) as string

      showStatus('Submitting proof to L1...', 'pending', 'withdraw')

      let receipt = null
      while (!receipt) {
        await new Promise(r => setTimeout(r, 3000))
        receipt = await rpc('eth_getTransactionReceipt', [txHash])
      }

      await Promise.all([updateBalance(), updateNotes(), updateTransactions()])
      setWithdrawAmount('')

      // Find the L1 hash from the latest transaction (last in array)
      const txList = await rpc('privacy_getTransactions', [account]) as Transaction[]
      const latestWithdraw = txList.filter(t => t.type === 'withdraw').pop()
      const l1Hash = latestWithdraw?.l1Hash

      showStatus('Withdrawal complete! ETH sent to your wallet.', 'success', 'withdraw', l1Hash)
    } catch (e) {
      setLoading(null)
      showStatus((e as Error).message, 'error', 'withdraw')
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
          <div className="bg-slate-800 rounded-xl p-4 space-y-3">
            {!account ? (
              <button
                onClick={connect}
                disabled={!!loading}
                className="w-full bg-cyan-500 hover:bg-cyan-400 disabled:bg-slate-600 disabled:cursor-not-allowed text-slate-900 font-semibold py-3 px-6 rounded-lg transition"
              >
                Connect Wallet
              </button>
            ) : (
              <>
                <p className="text-slate-400 text-sm">
                  Sign a message to create a viewing key and register it with the privacy adapter. The adapter can see your private transactions but it cannot spend your funds. This requires some trust, but you can always run your own adapter instance instead.
                </p>
                <button
                  onClick={register}
                  disabled={!!loading}
                  className="w-full bg-cyan-500 hover:bg-cyan-400 disabled:bg-slate-600 disabled:cursor-not-allowed text-slate-900 font-semibold py-3 px-6 rounded-lg transition"
                >
                  {loading === 'register' ? 'Signing...' : 'Login to Private Wallet'}
                </button>
              </>
            )}
            {/* Global status for connect/register */}
            {status && !status.section && <StatusDisplay status={status} elapsedTime={elapsedTime} />}
          </div>
        )}

        {/* Session Lost Banner */}
        {registered && sessionLost && (
          <div className="bg-red-500/20 border border-red-500/50 rounded-xl p-4 text-red-400">
            <div className="font-semibold mb-1">Session Expired</div>
            <p className="text-sm mb-3">
              The server was restarted and your session was lost. Please refresh the page to re-login.
            </p>
            <button
              onClick={() => window.location.reload()}
              className="bg-red-500 hover:bg-red-400 text-white font-semibold py-2 px-4 rounded-lg transition"
            >
              Refresh Page
            </button>
          </div>
        )}

        {/* L1 Section */}
        {registered && !sessionLost && (
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
                {loading === 'deposit' ? '...' : 'Deposit to L2'}
              </button>
            </div>
            {/* Deposit status */}
            {status?.section === 'deposit' && <StatusDisplay status={status} elapsedTime={elapsedTime} />}
          </div>
        )}

        {/* L2 Section */}
        {registered && !sessionLost && (
          <div className="bg-slate-800 rounded-xl p-4 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="text-cyan-400 font-semibold">L2 Facet Private</div>
                <button
                  onClick={refreshAll}
                  disabled={!!loading}
                  className="p-1 text-slate-500 hover:text-cyan-400 disabled:opacity-50 transition"
                  title="Refresh"
                >
                  <svg className={`w-4 h-4 ${loading === 'refresh' ? 'animate-spin' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                  </svg>
                </button>
              </div>
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
              {/* Transfer status */}
              {status?.section === 'transfer' && <StatusDisplay status={status} elapsedTime={elapsedTime} />}
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
              {/* Withdraw status */}
              {status?.section === 'withdraw' && <StatusDisplay status={status} elapsedTime={elapsedTime} />}
            </div>

            {/* Notes */}
            {unspentNotes.length > 0 && (
              <div className="pt-2 border-t border-slate-700">
                <div className="text-slate-400 text-sm mb-2">Notes ({unspentNotes.length})</div>
                <div className="flex flex-wrap gap-2">
                  {unspentNotes.map((note) => (
                    <div key={note.commitment} className="bg-slate-700 rounded px-2 py-1 text-sm text-cyan-400">
                      {formatEther(BigInt(note.amount))} ETH
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Transaction History */}
            {transactions.length > 0 && (
              <div className="pt-2 border-t border-slate-700">
                <div className="text-slate-400 text-sm mb-2">History</div>
                <div className="space-y-2">
                  {transactions.slice().reverse().map((tx) => (
                    <a
                      key={tx.l1Hash}
                      href={`${ETHERSCAN_URL}${tx.l1Hash}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center justify-between p-2 bg-slate-700 rounded hover:bg-slate-600 transition"
                    >
                      <div className="flex items-center gap-2">
                        <span className={`text-xs font-medium px-1.5 py-0.5 rounded ${
                          tx.type === 'deposit' ? 'bg-emerald-500/20 text-emerald-400' :
                          tx.type === 'transfer_in' ? 'bg-purple-500/20 text-purple-400' :
                          tx.type === 'transfer_self' ? 'bg-slate-500/20 text-slate-400' :
                          (tx.type === 'transfer' || tx.type === 'transfer_out') ? 'bg-cyan-500/20 text-cyan-400' :
                          'bg-orange-500/20 text-orange-400'
                        }`}>
                          {tx.type === 'deposit' ? 'Deposit' :
                           tx.type === 'transfer_in' ? 'Receive' :
                           tx.type === 'transfer_self' ? 'Self' :
                           (tx.type === 'transfer' || tx.type === 'transfer_out') ? 'Send' : 'Withdraw'}
                        </span>
                        <span className="text-slate-300 text-sm">
                          {formatEther(BigInt(tx.amount))} ETH
                        </span>
                        {tx.recipient && (tx.type === 'transfer' || tx.type === 'transfer_out') && (
                          <span className="text-slate-500 text-xs">
                            to {tx.recipient.slice(0, 6)}...{tx.recipient.slice(-4)}
                          </span>
                        )}
                      </div>
                      <svg className="w-4 h-4 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                      </svg>
                    </a>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

export default App

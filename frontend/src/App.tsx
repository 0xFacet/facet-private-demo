import { useState, useEffect, useCallback } from 'react'

// Configuration
const ADAPTER_URL = 'http://localhost:8546'
const WITHDRAW_SENTINEL = '0x0000000000000000000000000000000000000001'
const VIRTUAL_CHAIN_ID = '0xcc07c9' // 13371337

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

// RPC helper
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
  return BigInt(Math.floor(parseFloat(eth) * 1e18))
}

function formatEther(wei: bigint): string {
  return (Number(wei) / 1e18).toFixed(4)
}

function App() {
  const [account, setAccount] = useState<string | null>(null)
  const [registered, setRegistered] = useState(false)
  const [balance, setBalance] = useState<string>('--')
  const [notes, setNotes] = useState<Note[]>([])
  const [status, setStatus] = useState<{ message: string; type: 'success' | 'error' | 'pending' } | null>(null)
  const [loading, setLoading] = useState<string | null>(null) // What operation is in progress

  // Form state
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
      const bal = await rpc('eth_getBalance', [account, 'latest']) as string
      setBalance(formatEther(BigInt(bal)) + ' ETH')
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
      setAccount(accounts[0])
      showStatus('Wallet connected!')

      // Try to switch to our network
      try {
        await window.ethereum.request({
          method: 'wallet_switchEthereumChain',
          params: [{ chainId: VIRTUAL_CHAIN_ID }],
        })
      } catch (switchError: unknown) {
        if ((switchError as { code: number }).code === 4902) {
          await window.ethereum.request({
            method: 'wallet_addEthereumChain',
            params: [{
              chainId: VIRTUAL_CHAIN_ID,
              chainName: 'Facet Private (Demo)',
              rpcUrls: [ADAPTER_URL],
              nativeCurrency: { name: 'ETH', symbol: 'ETH', decimals: 18 },
            }],
          })
        } else {
          throw switchError
        }
      }
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
      })

      await rpc('privacy_registerViewingKey', [account, signature])
      setRegistered(true)
      showStatus('Viewing key registered! You can now use private transactions.')
    } catch (e) {
      setLoading(null)
      showStatus((e as Error).message, 'error')
    }
  }

  // Get Test ETH (fixed 0.01 ETH deposit, relayer pays)
  const getTestEth = async () => {
    try {
      setLoading('deposit')
      showStatus('Depositing 0.01 ETH (creating 2 shielded notes)...', 'pending')

      await rpc('privacy_getTestEth', [account])

      await Promise.all([updateBalance(), updateNotes()])
      showStatus('Deposit complete! 0.01 ETH added to your shielded balance.')
    } catch (e) {
      setLoading(null)
      showStatus((e as Error).message, 'error')
    }
  }

  // Transfer
  const transfer = async () => {
    try {
      if (!transferTo || !transferTo.startsWith('0x')) {
        throw new Error('Please enter a valid recipient address')
      }
      if (!transferAmount || parseFloat(transferAmount) <= 0) {
        throw new Error('Please enter a valid amount')
      }

      setLoading('transfer')
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

  // Withdraw
  const withdraw = async () => {
    try {
      if (!withdrawAmount || parseFloat(withdrawAmount) <= 0) {
        throw new Error('Please enter a valid amount')
      }

      setLoading('withdraw')
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

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-md mx-auto space-y-6">
        {/* Header */}
        <div className="text-center">
          <h1 className="text-3xl font-bold text-cyan-400">
            Facet Private
            <span className="ml-2 text-xs bg-orange-500/20 text-orange-400 px-2 py-1 rounded">
              Sepolia
            </span>
          </h1>
          <p className="text-slate-400 mt-1">Private ETH transactions with ZK proofs</p>
        </div>

        {/* Balance Card */}
        <div className="bg-slate-800 rounded-xl p-6">
          <div className="text-slate-400 text-sm">Shielded Balance</div>
          <div className="text-3xl font-bold text-cyan-400">{balance}</div>
          <div className="text-slate-500 text-xs font-mono mt-2 break-all">
            {account || 'Not connected'}
          </div>
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

        {/* Actions (shown when registered) */}
        {registered && (
          <>
            {/* Get Test ETH */}
            <div className="bg-slate-800 rounded-xl p-4">
              <button
                onClick={getTestEth}
                disabled={!!loading}
                className="w-full bg-emerald-500 hover:bg-emerald-400 disabled:bg-slate-600 disabled:cursor-not-allowed text-slate-900 disabled:text-slate-400 font-semibold py-3 px-6 rounded-lg transition"
              >
                {loading === 'deposit' ? 'Depositing...' : 'Get Test ETH (0.01 ETH)'}
              </button>
              <p className="text-slate-500 text-xs mt-2 text-center">
                Deposits 0.01 ETH from your wallet into the privacy pool
              </p>
            </div>

            {/* Transfer */}
            <div className="bg-slate-800 rounded-xl p-4 space-y-3">
              <div className="text-cyan-400 font-semibold">Private Transfer</div>
              <input
                type="text"
                placeholder="Recipient address (0x...)"
                value={transferTo}
                onChange={(e) => setTransferTo(e.target.value)}
                disabled={!!loading}
                className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-3 text-slate-100 placeholder-slate-400 focus:outline-none focus:border-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed"
              />
              <input
                type="text"
                placeholder="Amount in ETH"
                value={transferAmount}
                onChange={(e) => setTransferAmount(e.target.value)}
                disabled={!!loading}
                className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-3 text-slate-100 placeholder-slate-400 focus:outline-none focus:border-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed"
              />
              <button
                onClick={transfer}
                disabled={!!loading}
                className="w-full bg-cyan-500 hover:bg-cyan-400 disabled:bg-slate-600 disabled:cursor-not-allowed text-slate-900 disabled:text-slate-400 font-semibold py-3 px-6 rounded-lg transition"
              >
                {loading === 'transfer' ? 'Sending...' : 'Send Privately'}
              </button>
            </div>

            {/* Withdraw */}
            <div className="bg-slate-800 rounded-xl p-4 space-y-3">
              <div className="text-cyan-400 font-semibold">Withdraw</div>
              <input
                type="text"
                placeholder="Amount in ETH"
                value={withdrawAmount}
                onChange={(e) => setWithdrawAmount(e.target.value)}
                disabled={!!loading}
                className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-3 text-slate-100 placeholder-slate-400 focus:outline-none focus:border-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed"
              />
              <button
                onClick={withdraw}
                disabled={!!loading}
                className="w-full bg-cyan-500 hover:bg-cyan-400 disabled:bg-slate-600 disabled:cursor-not-allowed text-slate-900 disabled:text-slate-400 font-semibold py-3 px-6 rounded-lg transition"
              >
                {loading === 'withdraw' ? 'Withdrawing...' : 'Withdraw to Wallet'}
              </button>
            </div>

            {/* Notes */}
            <div className="bg-slate-800 rounded-xl p-4 space-y-3">
              <div className="text-cyan-400 font-semibold">Your Notes</div>
              <div className="max-h-48 overflow-y-auto space-y-2">
                {notes.length === 0 ? (
                  <div className="text-slate-500 text-sm">No notes yet</div>
                ) : (
                  notes.map((note, i) => (
                    <div
                      key={i}
                      className={`bg-slate-700 rounded-lg px-4 py-2 flex justify-between text-sm ${
                        note.spent ? 'opacity-50' : ''
                      }`}
                    >
                      <span>{formatEther(BigInt(note.amount))} ETH</span>
                      <span className="text-slate-400">{note.spent ? 'spent' : 'unspent'}</span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </>
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
              <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
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

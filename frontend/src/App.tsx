import { useState, useEffect, useCallback } from 'react'

// Configuration
const ADAPTER_URL = 'http://localhost:8546'
const POOL_ADDRESS = '0xeb41F491421336Ece3Dd43F060720a63bA917803'
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

  // Form state
  const [depositAmount, setDepositAmount] = useState('')
  const [transferTo, setTransferTo] = useState('')
  const [transferAmount, setTransferAmount] = useState('')
  const [withdrawAmount, setWithdrawAmount] = useState('')

  const showStatus = useCallback((message: string, type: 'success' | 'error' | 'pending' = 'success') => {
    setStatus({ message, type })
    if (type === 'success') {
      setTimeout(() => setStatus(null), 5000)
    }
  }, [])

  const updateBalance = useCallback(async () => {
    if (!account) return
    try {
      // Use privacy_getShieldedBalance for real balance (eth_getBalance has buffer for MetaMask)
      const bal = await rpc('privacy_getShieldedBalance', [account]) as string
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
      showStatus((e as Error).message, 'error')
    }
  }

  // Deposit
  const deposit = async () => {
    try {
      if (!depositAmount || parseFloat(depositAmount) <= 0) {
        throw new Error('Please enter a valid amount')
      }

      const weiAmount = '0x' + parseEther(depositAmount).toString(16)
      showStatus('Confirm deposit in MetaMask...', 'pending')

      const txHash = await window.ethereum!.request({
        method: 'eth_sendTransaction',
        params: [{ from: account, to: POOL_ADDRESS, value: weiAmount }],
      }) as string

      showStatus('Deposit submitted! Waiting for confirmation...', 'pending')

      let receipt = null
      while (!receipt) {
        await new Promise(r => setTimeout(r, 2000))
        receipt = await rpc('eth_getTransactionReceipt', [txHash])
      }

      showStatus('Deposit confirmed!')
      setDepositAmount('')
      updateBalance()
      updateNotes()
    } catch (e) {
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

      const weiAmount = '0x' + parseEther(transferAmount).toString(16)
      showStatus('Confirm transfer in MetaMask...', 'pending')

      const txHash = await window.ethereum!.request({
        method: 'eth_sendTransaction',
        params: [{ from: account, to: transferTo, value: weiAmount }],
      }) as string

      showStatus('Transfer submitted! Generating proof (this may take ~30 seconds)...', 'pending')

      let receipt = null
      while (!receipt) {
        await new Promise(r => setTimeout(r, 3000))
        receipt = await rpc('eth_getTransactionReceipt', [txHash])
      }

      showStatus('Transfer complete! Proof verified on Sepolia.')
      setTransferTo('')
      setTransferAmount('')
      updateBalance()
      updateNotes()
    } catch (e) {
      showStatus((e as Error).message, 'error')
    }
  }

  // Withdraw
  const withdraw = async () => {
    try {
      if (!withdrawAmount || parseFloat(withdrawAmount) <= 0) {
        throw new Error('Please enter a valid amount')
      }

      const weiAmount = '0x' + parseEther(withdrawAmount).toString(16)
      showStatus('Confirm withdrawal in MetaMask...', 'pending')

      const txHash = await window.ethereum!.request({
        method: 'eth_sendTransaction',
        params: [{ from: account, to: WITHDRAW_SENTINEL, value: weiAmount }],
      }) as string

      showStatus('Withdrawal submitted! Generating proof (this may take ~30 seconds)...', 'pending')

      let receipt = null
      while (!receipt) {
        await new Promise(r => setTimeout(r, 3000))
        receipt = await rpc('eth_getTransactionReceipt', [txHash])
      }

      showStatus('Withdrawal complete! ETH sent to your wallet.')
      setWithdrawAmount('')
      updateBalance()
      updateNotes()
    } catch (e) {
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
                className="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-900 font-semibold py-3 px-6 rounded-lg transition"
              >
                Connect Wallet
              </button>
            ) : (
              <button
                onClick={register}
                className="w-full bg-slate-700 hover:bg-slate-600 text-cyan-400 font-semibold py-3 px-6 rounded-lg transition"
              >
                Register Viewing Key
              </button>
            )}
          </div>
        )}

        {/* Actions (shown when registered) */}
        {registered && (
          <>
            {/* Deposit */}
            <div className="bg-slate-800 rounded-xl p-4 space-y-3">
              <div className="text-cyan-400 font-semibold">Deposit</div>
              <input
                type="text"
                placeholder="Amount in ETH (e.g., 0.01)"
                value={depositAmount}
                onChange={(e) => setDepositAmount(e.target.value)}
                className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-3 text-slate-100 placeholder-slate-400 focus:outline-none focus:border-cyan-500"
              />
              <button
                onClick={deposit}
                className="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-900 font-semibold py-3 px-6 rounded-lg transition"
              >
                Deposit to Pool
              </button>
            </div>

            {/* Transfer */}
            <div className="bg-slate-800 rounded-xl p-4 space-y-3">
              <div className="text-cyan-400 font-semibold">Private Transfer</div>
              <input
                type="text"
                placeholder="Recipient address (0x...)"
                value={transferTo}
                onChange={(e) => setTransferTo(e.target.value)}
                className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-3 text-slate-100 placeholder-slate-400 focus:outline-none focus:border-cyan-500"
              />
              <input
                type="text"
                placeholder="Amount in ETH"
                value={transferAmount}
                onChange={(e) => setTransferAmount(e.target.value)}
                className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-3 text-slate-100 placeholder-slate-400 focus:outline-none focus:border-cyan-500"
              />
              <button
                onClick={transfer}
                className="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-900 font-semibold py-3 px-6 rounded-lg transition"
              >
                Send Privately
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
                className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-3 text-slate-100 placeholder-slate-400 focus:outline-none focus:border-cyan-500"
              />
              <button
                onClick={withdraw}
                className="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-900 font-semibold py-3 px-6 rounded-lg transition"
              >
                Withdraw to Wallet
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
            className={`rounded-lg p-4 text-sm ${
              status.type === 'success'
                ? 'bg-cyan-500/20 text-cyan-400'
                : status.type === 'error'
                ? 'bg-red-500/20 text-red-400'
                : 'bg-orange-500/20 text-orange-400'
            }`}
          >
            {status.message}
          </div>
        )}
      </div>
    </div>
  )
}

export default App

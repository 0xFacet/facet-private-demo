import { useState, useEffect, useCallback, useRef } from 'react'
import { parseEther as viemParseEther, formatEther as viemFormatEther } from 'viem'
import { useAccount, useSignMessage, useSwitchChain, useSendTransaction, useWriteContract } from 'wagmi'
import { sepolia } from 'wagmi/chains'
import { ConnectButton } from '@rainbow-me/rainbowkit'
import { useTheme, type Theme } from './themes'
import { facetPrivate } from './wagmi'

// Configuration
const ADAPTER_URL = import.meta.env.VITE_ADAPTER_URL || 'http://localhost:8546'
const WITHDRAW_SENTINEL = '0x0000000000000000000000000000000000000001'

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
    { name: 'nullifierKeyHash', type: 'uint256' },
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

// Extract a tx hash from an error message (e.g. viem timeout errors)
function extractTxHash(message: string): string | undefined {
  const match = message.match(/0x[0-9a-fA-F]{64}/)
  return match?.[0]
}

// Clean up viem error messages for display
function cleanErrorMessage(message: string): string {
  return message
    .replace(/\s*Version: viem@[\d.]+\s*$/, '') // strip viem version suffix
    .replace(/"(0x[0-9a-fA-F]+)"/g, '$1')       // remove quotes around tx hashes
    .trim()
}

// Status display component
function StatusDisplay({ status, elapsedTime, theme: t }: { status: Status | null; elapsedTime: number; theme: Theme }) {
  if (!status) return null

  const txHash = status.txHash || (status.type === 'error' ? extractTxHash(status.message) : undefined)

  return (
    <div className={`p-3 text-sm flex items-center gap-3 rounded ${t.status[status.type]}`}>
      {status.type === 'pending' && (
        <svg className="animate-spin h-4 w-4 flex-shrink-0" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
        </svg>
      )}
      <div className="flex-1 min-w-0">
        <div className={`${t.statusText} break-words ${status.type === 'error' ? 'normal-case' : ''}`}>
          {status.type === 'error' ? cleanErrorMessage(status.message) : status.message}
        </div>
        {status.type === 'pending' && status.message.includes('proof') && (
          <div className="text-xs opacity-75 mt-1">
            {elapsedTime}s elapsed - proof generation takes ~60s on this demo server
          </div>
        )}
        {txHash && (status.type === 'success' || status.type === 'error') && (
          <a
            href={`${ETHERSCAN_URL}${txHash}`}
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
  const { address: account, isConnected } = useAccount()
  const { signMessageAsync } = useSignMessage()
  const { switchChainAsync } = useSwitchChain()
  const { sendTransactionAsync } = useSendTransaction()
  const { writeContractAsync } = useWriteContract()

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

  // Reset state when account changes or disconnects
  const prevAccountRef = useRef(account)
  useEffect(() => {
    if (prevAccountRef.current !== account) {
      prevAccountRef.current = account
      setRegistered(false)
      setBalance('--')
      setL1Balance('--')
      setNotes([])
      setTransactions([])
      setStatus(null)
      setLoading(null)
      setSessionLost(false)
    }
  }, [account])

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

  // Register viewing key
  const register = async () => {
    try {
      if (!account) return
      setLoading('register')
      showStatus('Please sign the message in your wallet...', 'pending')

      const lowerAccount = account.toLowerCase()
      const message = `Register viewing key for Facet Private\nAddress: ${lowerAccount}`
      const signature = await signMessageAsync({ message })

      await rpc('privacy_registerViewingKey', [lowerAccount, signature])

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
      await switchChainAsync({ chainId: sepolia.id })

      const amount = parseEther(depositAmount)
      const owner = BigInt(account!)
      const randomness = randomBigInt()

      showStatus('Fetching nullifier key hash...', 'pending', 'deposit')

      // Get nullifier key hash from adapter (stored in registry during registration)
      const nkHashHex = await rpc('privacy_getNullifierKeyHash', [account]) as `0x${string}`
      const nullifierKeyHash = BigInt(nkHashHex)

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

      showStatus('Confirm deposit in your wallet...', 'pending', 'deposit')

      const txHash = await writeContractAsync({
        address: PRIVACY_POOL_ADDRESS as `0x${string}`,
        abi: PRIVACY_POOL_ABI,
        functionName: 'deposit',
        args: [owner, randomness, nullifierKeyHash, encryptedNote],
        value: amount,
        chainId: sepolia.id,
      })

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

  // Transfer (via adapter)
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
      showStatus('Preparing transaction...', 'pending', 'transfer')
      await switchChainAsync({ chainId: facetPrivate.id })

      showStatus('Confirm in your wallet...', 'pending', 'transfer')

      const txHash = await sendTransactionAsync({
        to: transferTo as `0x${string}`,
        value: parseEther(transferAmount),
        chainId: facetPrivate.id,
      })

      // Transaction submitted - now poll for status
      // The RPC returns immediately, proof generation happens in background
      setProofStartTime(Date.now())
      showStatus('Generating zero-knowledge proof...', 'pending', 'transfer')

      let attempts = 0
      let unknownCount = 0
      const maxAttempts = 60 // ~3 minutes at 3s intervals
      let txStatus: { status: string; l1Hash?: string; error?: string } = { status: 'proving' }

      while (txStatus.status !== 'complete' && txStatus.status !== 'failed') {
        if (++attempts > maxAttempts) {
          throw new Error('Transaction timed out. Please check your balance and try again.')
        }
        await new Promise(r => setTimeout(r, 3000))
        txStatus = await rpc('privacy_getTransactionStatus', [txHash]) as typeof txStatus

        // Handle unknown status (transaction may have been lost)
        if (txStatus.status === 'unknown') {
          unknownCount++
          if (unknownCount > 3) {
            throw new Error('Transaction not found. It may have failed during submission.')
          }
        } else {
          unknownCount = 0 // Reset on valid status
        }

        // Update UI based on status
        if (txStatus.status === 'proving') {
          showStatus('Generating zero-knowledge proof...', 'pending', 'transfer')
        } else if (txStatus.status === 'submitting') {
          showStatus('Submitting proof on-chain...', 'pending', 'transfer')
        }
      }

      if (txStatus.status === 'failed') {
        throw new Error(txStatus.error || 'Transaction failed')
      }

      // Success
      await Promise.all([updateBalance(), updateNotes(), updateTransactions()])
      setTransferTo('')
      setTransferAmount('')

      showStatus('Transfer complete!', 'success', 'transfer', txStatus.l1Hash)
    } catch (e) {
      setLoading(null)
      showStatus((e as Error).message, 'error', 'transfer')
    }
  }

  // Withdraw (via adapter)
  const withdraw = async () => {
    try {
      if (!withdrawAmount || parseFloat(withdrawAmount) <= 0) {
        throw new Error('Please enter a valid amount')
      }

      setLoading('withdraw')

      // Ensure we're on virtual chain
      showStatus('Preparing transaction...', 'pending', 'withdraw')
      await switchChainAsync({ chainId: facetPrivate.id })

      showStatus('Confirm in your wallet...', 'pending', 'withdraw')

      const txHash = await sendTransactionAsync({
        to: WITHDRAW_SENTINEL as `0x${string}`,
        value: parseEther(withdrawAmount),
        chainId: facetPrivate.id,
      })

      // Transaction submitted - now poll for status
      // The RPC returns immediately, proof generation happens in background
      setProofStartTime(Date.now())
      showStatus('Generating zero-knowledge proof...', 'pending', 'withdraw')

      let attempts = 0
      let unknownCount = 0
      const maxAttempts = 60 // ~3 minutes at 3s intervals
      let txStatus: { status: string; l1Hash?: string; error?: string } = { status: 'proving' }

      while (txStatus.status !== 'complete' && txStatus.status !== 'failed') {
        if (++attempts > maxAttempts) {
          throw new Error('Transaction timed out. Please check your balance and try again.')
        }
        await new Promise(r => setTimeout(r, 3000))
        txStatus = await rpc('privacy_getTransactionStatus', [txHash]) as typeof txStatus

        // Handle unknown status (transaction may have been lost)
        if (txStatus.status === 'unknown') {
          unknownCount++
          if (unknownCount > 3) {
            throw new Error('Transaction not found. It may have failed during submission.')
          }
        } else {
          unknownCount = 0 // Reset on valid status
        }

        // Update UI based on status
        if (txStatus.status === 'proving') {
          showStatus('Generating zero-knowledge proof...', 'pending', 'withdraw')
        } else if (txStatus.status === 'submitting') {
          showStatus('Submitting proof on-chain...', 'pending', 'withdraw')
        }
      }

      if (txStatus.status === 'failed') {
        throw new Error(txStatus.error || 'Transaction failed')
      }

      // Success
      await Promise.all([updateBalance(), updateNotes(), updateTransactions()])
      setWithdrawAmount('')

      showStatus('Withdrawal complete! ETH sent to your wallet.', 'success', 'withdraw', txStatus.l1Hash)
    } catch (e) {
      setLoading(null)
      showStatus((e as Error).message, 'error', 'withdraw')
    }
  }

  const unspentNotes = notes.filter(n => !n.spent)
  const { theme: t, themeId, setThemeId, themes: allThemes } = useTheme()

  return (
    <div className={t.page}>
      <div className={t.container}>
        {/* Header */}
        <header className={t.header}>
          <div className="flex justify-between items-center">
            <div className="flex items-center">
              <div className={t.logoMark}>FP</div>
              <div className={t.logoText}>FACET<br />PRIVATE</div>
            </div>
            {account && (
              <ConnectButton.Custom>
                {({ account: acct, openAccountModal }) => (
                  <button onClick={openAccountModal} className={t.headerAddress}>
                    {acct?.ensName || (acct?.address ? `${acct.address.slice(0, 8)}...${acct.address.slice(-6)}` : '')}
                  </button>
                )}
              </ConnectButton.Custom>
            )}
          </div>
        </header>

        {/* Main Content */}
        <main className={t.main}>
          {/* Tagline */}
          <p className={t.tagline}>Private payments on Ethereum <span className="whitespace-nowrap">with your existing wallet</span></p>

          {/* Connect / Register */}
          {(!isConnected || !registered) && (
            <div className={`${t.card} p-4 space-y-3`}>
              {!isConnected ? (
                <>
                  <ConnectButton.Custom>
                    {({ openConnectModal }) => (
                      <button
                        onClick={openConnectModal}
                        disabled={!!loading}
                        className={`${t.btnAccent} w-full py-3 px-6`}
                      >
                        Connect Wallet
                      </button>
                    )}
                  </ConnectButton.Custom>
                  <div className={`text-left space-y-2 pt-2 ${t.infoText}`}>
                    <p><strong className={t.infoStrong}>Your keys, your funds.</strong> Your MetaMask private key is your spending key. The Privacy RPC generates ZK proofs but cannot spend without your signature.</p>
                    <p><strong className={t.infoStrong}>Deposits are public.</strong> When you deposit, observers see the amount. This is a tradeoff for simpler UX (no client-side proofs).</p>
                    <p><strong className={t.infoStrong}>Transfers are private.</strong> Transfers and withdrawals cannot be linked back to your deposits. That's the core privacy property.</p>
                    <p><strong className={t.infoStrong}>This is a demo.</strong> It proves the core tech works on Sepolia.</p>
                  </div>
                </>
              ) : (
                <>
                  <p className={t.infoText}>
                    Sign a message to set up your private wallet. The Privacy RPC generates proofs on your behalf — it can see your transfers but cannot spend your funds. You can run your own Privacy RPC instead.
                  </p>
                  <button
                    onClick={register}
                    disabled={!!loading}
                    className={`${t.btnAccent} w-full py-3 px-6`}
                  >
                    {loading === 'register' ? 'Signing...' : 'Login to Private Wallet'}
                  </button>
                </>
              )}
              {status && !status.section && <StatusDisplay status={status} elapsedTime={elapsedTime} theme={t} />}
            </div>
          )}

          {/* Session Lost Banner */}
          {registered && sessionLost && (
            <div className={t.sessionBanner}>
              <div className={t.sessionTitle}>Session Expired</div>
              <p className={t.sessionText}>
                The server was restarted and your session was lost. Please refresh the page to re-login.
              </p>
              <button onClick={() => window.location.reload()} className={t.btnDanger}>
                Refresh Page
              </button>
            </div>
          )}

          {/* Public Balance / Deposit Section */}
          {registered && !sessionLost && (
            <div className={t.card}>
              <div className={t.cardHeader}>
                <div className={`${t.balanceLabel} mb-1`}>PUBLIC BALANCE</div>
                <div className={t.balanceAmount}>{l1Balance} <span className={t.balanceUnit}>ETH</span></div>
              </div>
              <div className={`${t.cardSection} space-y-3`}>
                <p className={t.helpText}>Move ETH into your private balance. The deposit itself is visible on-chain, but once private, your transfers are not.</p>
                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder="Amount"
                    value={depositAmount}
                    onChange={(e) => setDepositAmount(e.target.value)}
                    disabled={!!loading}
                    className={`${t.input} flex-1`}
                  />
                  <button
                    onClick={deposit}
                    disabled={!!loading}
                    className={t.btnPrimary}
                  >
                    {loading === 'deposit' ? '...' : 'Make Private'}
                  </button>
                </div>
                {status?.section === 'deposit' && <StatusDisplay status={status} elapsedTime={elapsedTime} theme={t} />}
              </div>
            </div>
          )}

          {/* Private Balance Section */}
          {registered && !sessionLost && (
            <div className={t.card}>
              <div className={`${t.cardHeader} flex items-center justify-between`}>
                <div>
                  <div className="flex items-center gap-2">
                    <div className={t.balanceLabel}>PRIVATE BALANCE</div>
                    <button
                      onClick={refreshAll}
                      disabled={!!loading}
                      className={t.btnIcon}
                      title="Refresh"
                    >
                      <svg className={`w-3 h-3 ${loading === 'refresh' ? 'animate-spin' : ''}`} fill="none" stroke={t.refreshStroke} viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                      </svg>
                    </button>
                  </div>
                </div>
                <div className={t.balanceAmount}>{balance} <span className={t.balanceUnit}>ETH</span></div>
              </div>

              {/* Transfer */}
              <div className={`${t.cardSection} space-y-3`}>
                <div className={t.sectionTitle}>PRIVATE TRANSFER</div>
                <p className={t.helpText}>
                  Recipients must have registered with Facet Private.{' '}
                  <button
                    onClick={() => setTransferTo('0xc2172a6315c1d7f6855768f843c420ebb36eda97')}
                    className={t.link}
                  >
                    Use sample address
                  </button>
                </p>
                <input
                  type="text"
                  placeholder="Recipient (0x...)"
                  value={transferTo}
                  onChange={(e) => setTransferTo(e.target.value)}
                  disabled={!!loading}
                  className={`${t.input} w-full`}
                />
                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder="Amount"
                    value={transferAmount}
                    onChange={(e) => setTransferAmount(e.target.value)}
                    disabled={!!loading}
                    className={`${t.input} flex-1`}
                  />
                  <button
                    onClick={transfer}
                    disabled={!!loading}
                    className={t.btnAccent}
                  >
                    {loading === 'transfer' ? '...' : 'Send'}
                  </button>
                </div>
                {status?.section === 'transfer' && <StatusDisplay status={status} elapsedTime={elapsedTime} theme={t} />}
              </div>

              {/* Withdraw */}
              <div className={`${t.cardSection} space-y-3`}>
                <div className={t.sectionTitle}>WITHDRAW</div>
                <p className={t.helpText}>Move ETH back to your public wallet. The withdrawal is visible on-chain.</p>
                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder="Amount"
                    value={withdrawAmount}
                    onChange={(e) => setWithdrawAmount(e.target.value)}
                    disabled={!!loading}
                    className={`${t.input} flex-1`}
                  />
                  <button
                    onClick={withdraw}
                    disabled={!!loading}
                    className={t.btnAccent}
                  >
                    {loading === 'withdraw' ? '...' : 'Make Public'}
                  </button>
                </div>
                {status?.section === 'withdraw' && <StatusDisplay status={status} elapsedTime={elapsedTime} theme={t} />}
              </div>

              {/* Notes */}
              {unspentNotes.length > 0 && (
                <div className={t.cardSection}>
                  <div className="flex items-center gap-2 mb-2">
                    <span className={`${t.sectionTitle} text-sm`}>NOTES ({unspentNotes.length})</span>
                    <span className={t.helpText}>— encrypted UTXOs only you can spend</span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {unspentNotes.map((note) => (
                      <div key={note.commitment} className={t.notePill}>
                        {formatEther(BigInt(note.amount))} ETH
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Transaction History */}
              {transactions.length > 0 && (
                <div className={t.cardSection}>
                  <div className={`${t.sectionTitle} text-sm mb-2`}>HISTORY</div>
                  <div className="space-y-2">
                    {transactions.slice().reverse().map((tx) => (
                      <a
                        key={tx.l1Hash}
                        href={`${ETHERSCAN_URL}${tx.l1Hash}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className={t.txRow}
                      >
                        <div className="flex items-center gap-2">
                          <span className={`text-xs font-bold px-1.5 py-0.5 rounded ${
                            tx.type === 'deposit' ? t.txBadge.deposit :
                            tx.type === 'transfer_in' ? t.txBadge.receive :
                            tx.type === 'transfer_self' ? t.txBadge.self :
                            (tx.type === 'transfer' || tx.type === 'transfer_out') ? t.txBadge.send :
                            t.txBadge.withdraw
                          }`}>
                            {tx.type === 'deposit' ? 'Deposit' :
                             tx.type === 'transfer_in' ? 'Receive' :
                             tx.type === 'transfer_self' ? 'Self' :
                             (tx.type === 'transfer' || tx.type === 'transfer_out') ? 'Send' : 'Withdraw'}
                          </span>
                          <span className={t.txAmount}>
                            {formatEther(BigInt(tx.amount))} ETH
                          </span>
                          {tx.recipient && (tx.type === 'transfer' || tx.type === 'transfer_out') && (
                            <span className={t.txMeta}>
                              to {tx.recipient.slice(0, 6)}...{tx.recipient.slice(-4)}
                            </span>
                          )}
                        </div>
                        <svg className={t.txIcon} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                        </svg>
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </main>

        {/* Footer */}
        <div className={t.footer}>
          <a
            href="https://github.com/0xFacet/facet-private-demo"
            target="_blank"
            rel="noopener noreferrer"
            className={t.footerLink}
          >
            <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
              <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.17 6.839 9.49.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.604-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836c.85.004 1.705.114 2.504.336 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.167 22 16.418 22 12c0-5.523-4.477-10-10-10z" />
            </svg>
            View on GitHub
          </a>
          <span className={t.footerSep}>·</span>
          <a
            href="https://hackmd.io/@tomlehman/enshrined-privacy-pool-overview"
            target="_blank"
            rel="noopener noreferrer"
            className={t.footerLink}
          >
            Design Overview
          </a>
          <span className={t.footerSep}>·</span>
          <a
            href="https://hackmd.io/@tomlehman/enshrined-privacy-pool-eip"
            target="_blank"
            rel="noopener noreferrer"
            className={t.footerLink}
          >
            Full Spec
          </a>
        </div>
        <div className="flex items-center justify-center mt-3 gap-2">
          <span className={t.footerLink}>Theme:</span>
          <select value={themeId} onChange={(e) => setThemeId(e.target.value)} className={t.themePicker}>
            {allThemes.map(theme => (
              <option key={theme.id} value={theme.id}>{theme.name}</option>
            ))}
          </select>
        </div>
      </div>
    </div>
  )
}

export default App

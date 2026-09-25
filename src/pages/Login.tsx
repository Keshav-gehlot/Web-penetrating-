import React,{useState}from'react';
import{useLocation,useNavigate}from'react-router-dom';
import{Eye,EyeOff,ShieldCheck,Loader2,ArrowLeft}from'lucide-react';
import{login,requestPasswordReset,confirmPasswordReset}from'../lib/auth';

type Mode='login'|'forgot'|'reset';

export default function Login(){
 const nav=useNavigate();const loc=useLocation();
 const[email,setEmail]=useState('keshavgehlot18@gmail.com');const[password,setPassword]=useState('');
 const[token,setToken]=useState('');const[newPassword,setNewPassword]=useState('');
 const[show,setShow]=useState(false);const[error,setError]=useState('');const[message,setMessage]=useState('');
 const[busy,setBusy]=useState(false);const[mode,setMode]=useState<Mode>('login');

 async function submit(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setMessage('');
  try{
   if(mode==='login'){await login(email,password);const to=new URLSearchParams(loc.search).get('next')||'/dashboard';nav(to,{replace:true});return}
   if(mode==='forgot'){const result=await requestPasswordReset(email);setMessage(result.message);if(result.development_token){setToken(result.development_token);setMode('reset')}}
   else{await confirmPasswordReset(token,newPassword);setMessage('Password reset successfully. Sign in with your new password.');setPassword('');setNewPassword('');setToken('');setMode('login')}
  }catch(err){setError(err instanceof Error?err.message:'Request failed')}finally{setBusy(false)}
 }
 const back=()=>{setMode('login');setError('');setMessage('')};
 return <div className="min-h-screen bg-phantom-bg text-phantom-text-primary flex items-center justify-center p-6"><div className="w-full max-w-md">
  <div className="flex items-center gap-3 mb-8"><div className="w-11 h-11 rounded-xl border border-phantom-border bg-phantom-surface flex items-center justify-center"><ShieldCheck size={21} className="text-phantom-cyan"/></div><div><div className="font-semibold tracking-tight">PHANTOM</div><div className="text-xs text-phantom-text-tertiary">Security Operations Platform</div></div></div>
  <div className="rounded-2xl border border-phantom-border bg-phantom-surface p-6 shadow-2xl">
   {mode!=='login'&&<button type="button" onClick={back} className="mb-4 text-xs text-phantom-text-secondary flex items-center gap-1 hover:text-phantom-text-primary"><ArrowLeft size={14}/>Back to sign in</button>}
   <h1 className="text-xl font-semibold">{mode==='login'?'Sign in':mode==='forgot'?'Recover account':'Reset password'}</h1>
   <p className="text-sm text-phantom-text-secondary mt-1 mb-6">{mode==='login'?'Authenticate to access your security workspace.':mode==='forgot'?'Enter your account email to request password recovery.':'Enter the recovery token and choose a new password.'}</p>
   <form onSubmit={submit} className="space-y-4">
    {mode!=='reset'&&<label className="block"><span className="text-xs text-phantom-text-secondary">Email</span><input value={email} onChange={e=>setEmail(e.target.value)} type="email" autoComplete="username" required className="mt-1.5 w-full h-11 rounded-lg border border-phantom-border bg-phantom-bg px-3 outline-none focus:border-phantom-cyan"/></label>}
    {mode==='login'&&<label className="block"><span className="text-xs text-phantom-text-secondary">Password</span><div className="relative mt-1.5"><input value={password} onChange={e=>setPassword(e.target.value)} type={show?'text':'password'} autoComplete="current-password" required className="w-full h-11 rounded-lg border border-phantom-border bg-phantom-bg px-3 pr-11 outline-none focus:border-phantom-cyan"/><button type="button" onClick={()=>setShow(!show)} className="absolute right-3 top-1/2 -translate-y-1/2 text-phantom-text-tertiary">{show?<EyeOff size={16}/>:<Eye size={16}/>}</button></div></label>}
    {mode==='reset'&&<><label className="block"><span className="text-xs text-phantom-text-secondary">Recovery token</span><input value={token} onChange={e=>setToken(e.target.value)} required autoComplete="one-time-code" className="mt-1.5 w-full h-11 rounded-lg border border-phantom-border bg-phantom-bg px-3 outline-none focus:border-phantom-cyan"/></label><label className="block"><span className="text-xs text-phantom-text-secondary">New password</span><input value={newPassword} onChange={e=>setNewPassword(e.target.value)} type="password" minLength={8} required autoComplete="new-password" className="mt-1.5 w-full h-11 rounded-lg border border-phantom-border bg-phantom-bg px-3 outline-none focus:border-phantom-cyan"/></label></>}
    {error&&<div className="rounded-lg border border-phantom-coral/30 bg-phantom-coral/10 px-3 py-2 text-xs text-phantom-coral">{error}</div>}
    {message&&<div className="rounded-lg border border-phantom-cyan/30 px-3 py-2 text-xs text-phantom-text-secondary">{message}</div>}
    <button disabled={busy} className="w-full h-11 rounded-lg bg-phantom-text-primary text-black font-semibold text-sm flex items-center justify-center gap-2 disabled:opacity-50">{busy&&<Loader2 size={16} className="animate-spin"/>}{busy?'Please wait…':mode==='login'?'Continue':mode==='forgot'?'Request recovery':'Reset password'}</button>
   </form>
   {mode==='login'&&<button type="button" onClick={()=>{setMode('forgot');setError('');setMessage('')}} className="mt-4 w-full text-center text-xs text-phantom-cyan hover:underline">Forgot username or password?</button>}
   <div className="mt-5 text-[11px] text-phantom-text-tertiary">{mode==='login'?'Use your PHANTOM account credentials.':'For security, recovery requests do not reveal whether an account exists.'}</div>
  </div>
 </div></div>
}

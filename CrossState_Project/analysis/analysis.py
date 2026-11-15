import struct, sys, csv, json, collections
sys.path.insert(0,'.')
from ref.model import Ev, step, slot_of, canon, ALLOW, DROP
import matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot as plt, numpy as np
RUN="/path/to/mawi_runs/processed/run_20261113T143001Z/"  # EDIT THIS PATH
LIVE=RUN+"live_migration_bmv2_xdp/run_20261113T144904.552632Z/"
b=open(RUN+'mawi_crossstate_replay.pcap','rb').read()
off=24; evs=[]
while off<len(b):
    _,_,cl,_=struct.unpack('<IIII',b[off:off+16]); off+=16
    p=b[off:off+cl]; off+=cl
    ts=int.from_bytes(p[14:20],'big'); pid=int.from_bytes(p[20:24],'big'); d=p[24]
    ip=p[27:]; ihl=(ip[0]&15)*4; tl=struct.unpack('>H',ip[2:4])[0]
    sip=int.from_bytes(ip[12:16],'big'); dip=int.from_bytes(ip[16:20],'big'); proto=ip[9]
    sp,dp=struct.unpack('>HH',ip[ihl:ihl+4]); fl=ip[ihl+13]
    e=Ev(sip,sp,dip,dp,proto,d==1,bool(fl&2),bool(fl&16),bool(fl&1),bool(fl&4),tl,ts)
    evs.append((pid,slot_of(canon(e)),e))
print('packets',len(evs))
# phase map from live decisions
ph={}
for r in csv.DictReader(open(LIVE+'packet_decisions.csv')):
    ph[(int(r['slot']),int(r['packet_id']))]=r['phase']
phases=['A_INITIAL_SYN','A_REMAINDER_AFTER_MIGRATION','B_INITIAL_SYN','B_REMAINDER_AFTER_MIGRATION']
tgt={'A_INITIAL_SYN':'bmv2','A_REMAINDER_AFTER_MIGRATION':'xdp','B_INITIAL_SYN':'xdp','B_REMAINDER_AFTER_MIGRATION':'bmv2'}
byph=collections.defaultdict(list)
for pid,s,e in evs:
    k=(s,pid)
    if k in ph: byph[ph[k]].append((s,e))
print({k:len(v) for k,v in byph.items()}, sum(len(v) for v in byph.values()))
def run(migrate):
    T={'bmv2':{},'xdp':{}}; res={}; flows_bad=set()
    for p in phases:
        t=tgt[p]; other='xdp' if t=='bmv2' else 'bmv2'
        if p.endswith('REMAINDER_AFTER_MIGRATION') or p=='B_INITIAL_SYN':
            pass
        # checkpoint before A_REM (bmv2->xdp), before B_INITIAL (xdp->bmv2)... follow live schedule
        if p=='A_REMAINDER_AFTER_MIGRATION' and migrate: T['xdp']=dict(T['bmv2'])
        if p=='B_INITIAL_SYN' and migrate: T['bmv2']=dict(T['xdp'])
        if p=='B_REMAINDER_AFTER_MIGRATION' and migrate: T['bmv2']=dict(T['xdp'])
        a=d=0
        for s,e in byph[p]:
            r=step(T[t],e)
            if r==ALLOW: a+=1
            else: d+=1; flows_bad.add(canon(e))
        res[p]=(a,d)
    return res,len(flows_bad)
full,fb=run(True); cold,cb=run(False)
print('migrated',full,fb); print('cold',cold,cb)
json.dump({'migrated':full,'cold':cold,'flows_disrupted_cold':cb,'flows_disrupted_mig':fb},open('baseline.json','w'))
# fig baseline
lab=['A: SYN\n(BMv2)','A: rest\n(XDP)','B: SYN\n(XDP)','B: rest\n(BMv2)']
mig=[full[p][1]/sum(full[p])*100 for p in phases]; col=[cold[p][1]/sum(cold[p])*100 for p in phases]
x=np.arange(4); w=0.38
plt.figure(figsize=(3.5,2.5),dpi=220)
plt.bar(x-w/2,col,w,label='No migration (empty dest.)'); plt.bar(x+w/2,mig,w,label='CrossState')
plt.xticks(x,lab,fontsize=7); plt.ylabel('Packets dropped (%)',fontsize=8); plt.legend(fontsize=6.5,loc='center right'); plt.grid(axis='y',alpha=.3); plt.tight_layout()
plt.savefig('baseline_drop.png')
# parity scatter
import pandas as pd
s=pd.read_csv(LIVE+'mawi_final_flow_state.csv')
plt.figure(figsize=(3.4,2.4),dpi=220)
plt.loglog(s.packets_bmv2,s.packets_xdp,'.',ms=4,alpha=.6,label='packets'); plt.loglog(s.bytes_bmv2/100,s.bytes_xdp/100,'x',ms=3,alpha=.4,label='bytes / 100')
mx=max(s.packets_bmv2.max(),s.bytes_bmv2.max()/100); plt.plot([3,mx],[3,mx],'k--',lw=.8)
plt.xlabel('BMv2 counter',fontsize=8); plt.ylabel('XDP counter',fontsize=8); plt.legend(fontsize=6.5); plt.grid(alpha=.3); plt.tight_layout(); plt.savefig('parity.png')
# delta vs full + time per record
cp=['CP1\nB→X','CP2\nX→B','CP3\nX→B','CP4\nB→X']; full_w=[586,586,1086,1086]; delta=[500]*4
plt.figure(figsize=(3.4,2.4),dpi=220); x=np.arange(4)
plt.bar(x-.2,full_w,.4,label='Full-table write'); plt.bar(x+.2,delta,.4,label='Delta (changed only)')
for i in range(4): plt.text(x[i]+.2,delta[i]+15,'%d%%'%round((1-delta[i]/full_w[i])*100),ha='center',fontsize=6.5)
plt.xticks(x,cp,fontsize=7); plt.ylabel('Records written',fontsize=8); plt.legend(fontsize=6.5,loc='upper left'); plt.grid(axis='y',alpha=.3); plt.ylim(0,1300); plt.tight_layout(); plt.savefig('delta_full.png')
dur=[47.66,201.48,484.09,130.52]; spr=[d/500 for d in dur]; colr=['tab:orange','tab:blue','tab:blue','tab:orange']
plt.figure(figsize=(3.4,2.4),dpi=220); plt.bar(x,spr,color=colr)
for i,v in enumerate(spr): plt.text(i,v+.015,'%.2f'%v,ha='center',fontsize=7)
plt.xticks(x,cp,fontsize=7); plt.ylabel('Elapsed s per written record',fontsize=8); plt.grid(axis='y',alpha=.3)
from matplotlib.patches import Patch
plt.legend(handles=[Patch(color='tab:blue',label='dest. = BMv2'),Patch(color='tab:orange',label='dest. = XDP')],fontsize=6.5,loc='upper left'); plt.tight_layout(); plt.savefig('time_per_record.png')

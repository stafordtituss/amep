----------------------------- MODULE AMEPHolds -----------------------------
(***************************************************************************)
(* AMEP's hold and single-use rules: operation identity (spec 5.8.1),     *)
(* single-use and held approvals (5.10), and "not executed" call          *)
(* statements with observer independence (5.14, I10, I11).                *)
(*                                                                         *)
(* An agent issues calls; each names an operation and, optionally, a      *)
(* single-use approval. The server may execute any issued call that       *)
(* hasn't been fenced. Evidence arrives in any order:                     *)
(*   - "receipt":  the observer's receipt for an executed call;           *)
(*   - "ne_obs":   the observer's signed "not executed", which fences the *)
(*                 call (it can no longer execute), unless the observer   *)
(*                 may lie;                                                *)
(*   - "ne_actor": a "not executed" signed by the actor's own key, true   *)
(*                 or not.                                                 *)
(* The verifier sees every issued call (the completeness assumption,      *)
(* LIMITS.md section A) and the evidence that has arrived.                *)
(*                                                                         *)
(* formal/explore.py walks the same state space and checks the same       *)
(* properties, and checks Verdicts against AMEP's Python verifier on      *)
(* every reachable evidence view. See formal/README.md.                   *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS MaxCalls,        \* bound on issued calls
          Ops,             \* operation identifiers
          Aps,             \* approval identifiers, including NoAp
          NoAp,            \* "this call cites no approval"
          HighImpact,      \* TRUE: write_shared or above, so I10 applies
          ObserverMayLie   \* TRUE: the observer may sign "not executed" and execute anyway

VARIABLES calls,     \* Seq of [op |-> o, ap |-> a], in issue order
          executed,  \* indices of calls that took effect
          fenced,    \* indices of calls the observer has excluded
          ev         \* evidence: a set of [k |-> kind, c |-> index]

vars == <<calls, executed, fenced, ev>>
Idx == 1..Len(calls)
E(k, i) == [k |-> k, c |-> i]

Init == calls = <<>> /\ executed = {} /\ fenced = {} /\ ev = {}

Issue(o, a) == /\ Len(calls) < MaxCalls
               /\ calls' = Append(calls, [op |-> o, ap |-> a])
               /\ UNCHANGED <<executed, fenced, ev>>
Execute(i) == /\ i \notin executed /\ i \notin fenced
              /\ executed' = executed \cup {i}
              /\ UNCHANGED <<calls, fenced, ev>>
Receipt(i) == /\ i \in executed
              /\ ev' = ev \cup {E("receipt", i)}
              /\ UNCHANGED <<calls, executed, fenced>>
ObserverNotExecuted(i) == /\ (i \notin executed \/ ObserverMayLie)
                          /\ ev' = ev \cup {E("ne_obs", i)}
                          /\ fenced' = fenced \cup {i}
                          /\ UNCHANGED <<calls, executed>>
ActorNotExecuted(i) == /\ ev' = ev \cup {E("ne_actor", i)}
                       /\ UNCHANGED <<calls, executed, fenced>>

Next == \/ \E o \in Ops, a \in Aps : Issue(o, a)
        \/ \E i \in Idx : Execute(i) \/ Receipt(i) \/ ObserverNotExecuted(i) \/ ActorNotExecuted(i)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* The verifier, as one pass over the calls in issue order (spec 10.2).   *)
(***************************************************************************)
HasR(i)   == E("receipt", i) \in ev
Stated(i) == E("ne_obs", i) \in ev \/ E("ne_actor", i) \in ev
\* I10: for a high-impact call the actor's own key shows nothing (5.14 rule 5)
Shown(i)  == E("ne_obs", i) \in ev \/ (~HighImpact /\ E("ne_actor", i) \in ev)

RECURSIVE Pass(_)
Pass(n) ==
  IF n = 0 THEN [opDone |-> {}, opHeld |-> {}, apUsed |-> {}, apHeld |-> {}, res |-> <<>>]
  ELSE LET s == Pass(n - 1)
           o == calls[n].op
           a == calls[n].ap
           unknown == ~HasR(n) /\ ~Shown(n)
           r == CASE HasR(n) /\ Stated(n)                                   -> "violated"   \* I11
                  [] HasR(n) /\ a # NoAp /\ a \in s.apUsed                  -> "violated"   \* I8
                  [] HasR(n) /\ o \in s.opDone                              -> "violated"   \* I2
                  [] HasR(n) /\ ((a # NoAp /\ a \in s.apHeld) \/ o \in s.opHeld) -> "unresolved" \* held_outcome
                  [] HasR(n) \/ Shown(n)                                    -> "preserved"
                  [] OTHER                                                  -> "unresolved" \* receipt, or I10
           ran     == HasR(n) /\ ~Stated(n)     \* a verified, uncontradicted receipt: the operation ran
           counts  == HasR(n) /\ r # "violated"   \* a violated call is charged once, for its first violation
       IN [opDone |-> IF ran THEN s.opDone \cup {o} ELSE s.opDone,
           opHeld |-> IF unknown /\ o \notin s.opDone THEN s.opHeld \cup {o} ELSE s.opHeld,
           apUsed |-> IF counts /\ a # NoAp THEN s.apUsed \cup {a} ELSE s.apUsed,
           apHeld |-> IF unknown /\ a # NoAp /\ a \notin s.apUsed THEN s.apHeld \cup {a} ELSE s.apHeld,
           res    |-> Append(s.res, r)]

Res == Pass(Len(calls)).res

(***************************************************************************)
(* Properties.                                                             *)
(***************************************************************************)
Lie == \E i \in Idx : (E("ne_obs", i) \in ev \/ E("ne_actor", i) \in ev) /\ i \in executed
Double(i, j) == /\ i < j /\ i \in executed /\ j \in executed
                /\ (calls[i].op = calls[j].op \/ (calls[i].ap # NoAp /\ calls[i].ap = calls[j].ap))

\* A double use is never left unreported: the later call is preserved only if the earlier is violated.
Sound == \A i, j \in Idx : Double(i, j) /\ Res[j] = "preserved" => Res[i] = "violated"

\* violated only when a call really took effect twice, or a signed statement is false.
NoFalseAlarm == (\E i \in Idx : Res[i] = "violated") =>
                    (Lie \/ \E i, j \in Idx : Double(i, j))

\* Once every outcome is shown and nobody lied, nothing is unresolved.
Complete == \A i \in Idx : IF i \in executed THEN HasR(i) ELSE E("ne_obs", i) \in ev
Settles == Complete /\ ~Lie => \A i \in Idx : Res[i] # "unresolved"

\* A preserved result stays preserved as evidence arrives, unless someone signs a false statement.
Stable == [][~Lie' => \A i \in Idx : Res[i] = "preserved" => Res'[i] = "preserved"]_vars

=============================================================================

# CloudTrail analysis (flaws.cloud public dataset)

1,939,207 events, 2017-02-12 19:57:06 to 2020-10-07 21:03:30, 116 distinct principals. Loaded by `python -m analytics.cloudtrail`.

> Caveat: flaws.cloud is a security CTF, so most of this traffic is players enumerating the API with leaked keys. It is a good scale and anomaly test, but 'observed usage' here is attacker behaviour, not a healthy baseline. A least-privilege policy built from it would freeze that behaviour in.

## Who calls the API

| identity type | events | principals |
|---|---|---|
| IAMUser | 1825650 | 7 |
| AWSService | 57616 | 1 |
| AssumedRole | 42315 | 51 |
| Root | 10997 | 1 |
| AWSAccount | 2628 | 57 |
| None | 1 | 1 |

## Granted vs used: distinct actions per principal

Observed usage is the only half we have here (CloudTrail does not show what a principal was *allowed* to do). Actions are `service:Event`; a least-privilege policy for a principal is exactly this set.

| principal | events | distinct actions | source IPs |
|---|---|---|---|
| arn:aws:iam::811596193553:user/backup | 915834 | 1176 | 5293 |
| arn:aws:iam::811596193553:user/Level6 | 905082 | 1016 | 1846 |
| unknown | 57643 | 4 | 55 |
| arn:aws:sts::811596193553:assumed-role/flaws/i-aa2d3b42e5c6e801a | 17208 | 808 | 651 |
| arn:aws:sts::811596193553:assumed-role/SecurityMonkey/secmonkey | 12354 | 47 | 2 |
| arn:aws:iam::811596193553:root | 10997 | 269 | 39 |
| arn:aws:iam::811596193553:user/SecurityMokey | 4522 | 1 | 1 |
| arn:aws:sts::811596193553:assumed-role/Level6/Level6 | 4190 | 2 | 3482 |
| arn:aws:sts::811596193553:assumed-role/SecurityMonkey/cloudaux | 3993 | 27 | 1 |
| arn:aws:sts::811596193553:assumed-role/aws:ec2-instance/i-aa2d3b42e5c6e801a | 2611 | 714 | 111 |

## Probable reconnaissance: principals with high denial rates

| principal | events | denied | % denied |
|---|---|---|---|
| 372138444324 | 371 | 371 | 100.0 |
| AIDAVFABPH102ZH4LMP0M | 87 | 87 | 100.0 |
| AIDA994EJ5S2EOGMFDHEV | 23 | 23 | 100.0 |
| arn:aws:sts::811596193553:assumed-role/flaws/i-aa2d3b42e5c6e801a | 17208 | 16123 | 93.7 |
|  | 1125 | 1042 | 92.6 |
| arn:aws:sts::811596193553:assumed-role/aws:ec2-instance/i-aa2d3b42e5c6e801a | 2611 | 2372 | 90.8 |
| arn:aws:iam::811596193553:user/backup | 915834 | 241853 | 26.4 |
| arn:aws:iam::811596193553:user/Level6 | 905082 | 211807 | 23.4 |
| arn:aws:iam::811596193553:user/Level5 | 39 | 2 | 5.1 |
| arn:aws:iam::811596193553:user/SecurityMokey | 4522 | 53 | 1.2 |

## Daily volume spikes (z-score >= 3 against the principal's own days)

| principal | day | events | z |
|---|---|---|---|
| arn:aws:iam::811596193553:user/backup | 2019-08-22 | 280666 | 25.9 |
| arn:aws:iam::811596193553:user/Level6 | 2019-08-22 | 310910 | 22.7 |
| arn:aws:iam::811596193553:user/backup | 2019-08-21 | 205016 | 18.9 |
| arn:aws:sts::811596193553:assumed-role/flaws/i-aa2d3b42e5c6e801a | 2020-06-11 | 4197 | 16.1 |
| arn:aws:iam::811596193553:user/Level6 | 2019-08-21 | 216280 | 15.7 |
| arn:aws:iam::811596193553:user/backup | 2019-08-23 | 145114 | 13.4 |
| arn:aws:iam::811596193553:user/Level6 | 2019-08-23 | 156182 | 11.4 |
| arn:aws:sts::811596193553:assumed-role/flaws/i-aa2d3b42e5c6e801a | 2020-05-24 | 2219 | 8.4 |
| null | 2020-07-06 | 49 | 8.1 |
| arn:aws:sts::811596193553:assumed-role/aws:ec2-instance/i-aa2d3b42e5c6e801a | 2020-10-06 | 1121 | 7.6 |

## Clients (user agent family)

| client | events | principals |
|---|---|---|
| Boto3 | 1561172 | 21 |
| aws-cli | 172604 | 25 |
| [Boto3 | 64457 | 36 |
| ec2.amazonaws.com | 44158 | 2 |
| [aws-cli | 17695 | 25 |
| aws-sdk-nodejs | 11321 | 4 |
| aws-sdk-java | 11122 | 3 |
| config.amazonaws.com | 7833 | 5 |

## Generated least-privilege policy

For `arn:aws:iam::811596193553:user/backup`: 1176 distinct actions observed. Policy written to `analytics/out/cloudtrail_least_privilege.json`. Replay check: every event this principal made is covered by construction; the real validation is holding out a later time slice, as done for Warden's own logs in `analytics/report.md`.

Holdout replay (learn on first 70% of this principal's time span, replay the rest): 8943 of 118211 later events would have been denied (673 distinct actions).

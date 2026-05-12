# Correction & Attribution Update — m0nkrus

---

## Short TL;DR

I was wrong. I linked your releases to an infostealer without the evidence to back that up — **using your file is not the same as your involvement**, and I missed that distinction entirely.

Your statements check out: the checksums are yours, and the `installer.msi` your question references doesn't exist anywhere in your repacks. The infostealer is real, but someone else used your legitimate `setup.exe` as a front. rocket1337 analyzed the package correctly and in good faith. The bad call was mine.

**m0nkrus has no connection to this. His releases are clean. I'm correcting the report. If you want the repository and everything associated with it taken down, just reply to your most recent comment on the Illustrator 30.3 page on your site — specifically the message from user "the name" — and I'll know you're referring to this. That's enough.**

---

# Full Version

I got this wrong — specifically where the files came from. I linked things that had no real connection. Most of it came from public data, and I didn't stop to question an association I should have questioned. I was already mid-correction when m0nkrus commented.

---

## On m0nkrus's Response

Both statements hold up. *"The checksums for my file are listed there"* — yes. *"It says it uses a certain Installer.msi. Can you find it in my repacks?"* — no, because it doesn't exist. There's no `installer.msi` anywhere in his releases, and that was the clearest tell I walked right past.

The infostealer is real. But m0nkrus didn't build it or put it out. **Someone using his file doesn't make him responsible for what was bundled alongside it**, and I didn't make that clear in the original analysis. The only link between his work and this infostealer is that the threat actor used his release as cover — without his knowledge — to make the package look legitimate.

---

## How the Misattribution Happened

The infostealer traces back to this Reddit post:
[https://www.reddit.com/r/huion/s/GNW09xTEve](https://www.reddit.com/r/huion/s/GNW09xTEve)

User **Onep2** had already flagged it at the time:

> *"Be careful with that crack, because it's a bit dodgy. During installation, there's a point where it asks for administrator permissions to 'make changes', but it never specifies what's being installed or why. It doesn't mention Photoshop at all during that step. The most suspicious thing is that if you cancel that request, the installation carries on regardless without any problems. If that permission were really necessary to install Photoshop, you'd normally expect it to fail or stop, but that doesn't happen. That suggests that the permission is actually for installing other things on the side, without you knowing. After installing it, a programme called 'Planora' appears on the system — never mentioned during the process. I don't have the advanced knowledge to analyse everything it does in the background, but these behaviours alone are enough to raise serious concerns."*

The post had three links attached:

1. A link to Adobe
2. A **MediaFire** download — a platform m0nkrus has never used for distribution, which alone should have ruled him out
3. A VirusTotal page with the hash results of the analyzed file

That hash is m0nkrus's legitimate `setup.exe`. The malicious distributor bundled it with the infostealer to make the package look clean.

rocket1337 found the package, downloaded it, identified the infostealer, and posted his findings to that same VirusTotal page — the one already linked in the Reddit post, same as he did with the other files in the chain. The `setup.exe` is genuinely m0nkrus's. It was just used as cover. With that VirusTotal link right there in the post, it was a reasonable read. I found the submission later, saw the hash tied to the chain, and ran with it without asking how it got there.

---

## To Be Clear

| Entity         | Clarification                                                       |
| -------------- | ------------------------------------------------------------------- |
| **m0nkrus**    | No connection to this infostealer. His releases are clean.          |
| **rocket1337** | Not at fault. Analyzed correctly and in good faith.                 |
| **Me**         | Linked unrelated elements and published without enough verification. |

---

## Direct Note to m0nkrus

You have every right to be unsatisfied. I accused you incorrectly, and I'm not looking for sympathy or a pass — I'm the one who got this wrong.

If you want the repository gone, say so. Reply here or in the Illustrator 30.3 discussion and I'll take it down. It's the only concrete thing I can do at this point, and the call is yours.

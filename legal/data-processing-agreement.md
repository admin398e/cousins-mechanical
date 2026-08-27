# Data Processing Agreement

**Between Cousins Mechanical Services Ltd (the Controller) and the supplier who
builds and runs its website and booking system (the Processor).**

---

## Read this first

**This is a draft for a solicitor to check, not legal advice.** I am not a
lawyer. What follows is written to cover everything Article 28(3) of the UK GDPR
requires a controller–processor contract to contain, using the real facts of
this system rather than boilerplate — but whether it is right for your two
businesses is a question for someone qualified, and it is cheap to ask.

**Why it has to exist at all.** Article 28(3) says a controller may only use a
processor under a written contract. It is not optional and it is not satisfied
by a handshake or an invoice. If the ICO ever asks Cousins how its customer data
is looked after, the first thing they will ask for is this document. Without it
both parties are in breach before anyone has even looked at the security.

**Who is who.** Cousins Mechanical Services Ltd decides what customer data is
collected and why, so Cousins is the **controller**. The supplier hosts the
system and acts on Cousins' instructions, so the supplier is the **processor**.
That split is what makes this the right kind of agreement; if the supplier
started deciding on its own account what to do with customer data — using it to
market its own services, say — it would become a controller in its own right and
this document would no longer describe reality.

**Before signing, fill in every `[SQUARE BRACKET]`.** They are deliberately
conspicuous. A contract signed with placeholders still in it is worse than no
contract, because it looks like diligence and is not.

---

## 1. Parties

**The Controller:** Cousins Mechanical Services Ltd, a company registered in
England and Wales, company number 16045339, registered office 7 Watton Park,
Bridport, DT6 5NJ ("Cousins").

**The Processor:** `[FULL LEGAL NAME]` of `[REGISTERED OFFICE OR TRADING
ADDRESS]`, `[COMPANY NUMBER, IF A LIMITED COMPANY — otherwise state "a sole
trader"]` ("the Supplier").

This agreement starts on `[DATE]` and runs for as long as the Supplier processes
personal data on Cousins' behalf.

---

## 2. What is being processed

This section exists because Article 28(3) requires the contract to set out the
subject matter, duration, nature and purpose of the processing, the types of
personal data and the categories of data subject. Vague answers here are the
most common reason a DPA fails to do its job.

**Subject matter and purpose.** Operating the Cousins website, online booking
system, customer records, driver application and the messages sent to customers
about their jobs.

**Duration.** For as long as the Supplier provides those services, plus the time
needed to return or delete the data afterwards under section 9.

**Nature of the processing.** Collection, storage, organisation, retrieval,
transmission to the sub-processors listed in section 6, and erasure.

**Categories of data subject.** Customers and enquirers of Cousins; drivers and
staff who hold logins to the system.

**Types of personal data.**

| Category | What it is |
| --- | --- |
| Identity and contact | Name, email address, mobile and landline numbers |
| Location | Postcode, address or map pin for the job |
| Vehicle | Registration, make, model |
| Job records | What was booked, when, what was done, what was charged |
| Correspondence | Messages between the customer and Cousins |
| Marketing preferences | Whether consent was given, and when it was withdrawn |
| Account credentials | Password hashes and salts for customer, driver and staff logins |
| Approximate live location | A driver's position while they are sharing it on an active job |
| Payment records | The fact and amount of a payment, and SumUp's reference for it |

**No special category data and no criminal offence data** is knowingly collected
by the system. Free-text note fields could in principle contain anything a
person types, which is a reason to keep notes factual and about the vehicle.

**Card details are never processed by the Supplier.** Card numbers are entered
on SumUp's own hosted checkout page and never reach the Cousins system, so
Cousins is in scope for SAQ-A rather than the far heavier SAQ-D.

---

## 3. The Supplier's obligations

The Supplier shall:

**(a) Act only on instructions.** Process personal data only on Cousins'
documented instructions, including on transfers out of the UK, unless required
otherwise by law — and where the law requires it, tell Cousins first unless the
law forbids that too.

**(b) Keep people bound to confidence.** Ensure anyone authorised to process the
data is under a duty of confidentiality.

**(c) Secure it.** Take the measures required by Article 32. What is actually in
place today is listed in section 5, so this clause is checkable rather than
decorative.

**(d) Not sub-contract without permission.** Engage no new sub-processor without
Cousins' prior written authorisation, and impose the same obligations on any it
does engage. The sub-processors already authorised are listed in section 6.

**(e) Help with data subject requests.** Assist Cousins in responding to
requests for access, correction, erasure, restriction, portability and
objection. The system has admin tools for finding and deleting a customer's
records; the Supplier will help where those are not enough.

**(f) Help with breaches, assessments and consultation.** Assist Cousins with
Articles 32 to 36, taking into account what the Supplier knows and can see.

**(g) Delete or return at the end.** At Cousins' choice, delete or return all
personal data at the end of the engagement, and delete existing copies unless
the law requires them to be kept. See section 9.

**(h) Make it possible to check.** Make available the information needed to
demonstrate compliance with Article 28, and allow and contribute to audits and
inspections by Cousins or an auditor it appoints.

---

## 4. Breach notification

The Supplier shall notify Cousins **without undue delay and in any event within
24 hours** of becoming aware of a personal data breach.

The 24 hours is deliberately tighter than the 72 hours Cousins itself gets under
Article 33. Cousins' clock starts when it is told, so a supplier who takes 48
hours to pass the news on has spent two thirds of the controller's budget before
the controller knows anything has happened.

The notification shall describe, as far as known: what happened, which
categories and roughly how many people and records are affected, the likely
consequences, and what is being done about it. Incomplete information is not a
reason to delay the first notification — send what is known and follow up.

---

## 5. Security measures actually in place

Article 32 asks for measures appropriate to the risk. These are the ones this
system has today. They are listed so that this contract can be checked against
reality, and so that anything that stops being true becomes obviously wrong
rather than quietly wrong.

- **Encryption in transit.** HTTPS is enforced on every page and every API call.
- **Passwords are never stored.** Customer, driver and staff passwords are held
  as PBKDF2 hashes with a per-record random salt and a server-side pepper held
  outside the database.
- **Two-factor authentication** is available on the owner's admin account.
- **Sign in with Google.** Staff may sign in with the business Google account
  instead of a password, in which case Google's own account security applies.
  Google sign-in never creates an account: the address must already exist as a
  staff login, so it grants no access on its own.
- **Least privilege, enforced.** Staff logins are separate named accounts with
  one of three roles — owner, developer, staff — and the role is checked on
  every administrative action, not merely displayed. A developer account cannot
  delete, disable or demote an owner, so a contractor with a login can never
  lock Cousins out of its own business. The last remaining owner cannot be
  removed. Wholesale costs and margins are never sent to the public site.
- **Third-party accounts are connected, not handed over.** Google Calendar and
  SumUp are linked by Cousins signing in to its own accounts through a consent
  screen; the resulting tokens are held server-side. No password or API key for
  a Cousins account is shared with the Supplier or typed into this system.
- **Rate limiting** on authentication, lookups and bookings, to blunt
  credential-stuffing and scraping.
- **Session handling.** Admin sessions live in `sessionStorage` and expire; the
  dashboard signs itself out after 30 minutes of inactivity.
- **Audit log** of administrative actions, retained for 12 months, recording the
  named account that performed each one rather than a shared login.
- **Spend limits** on outbound messaging, so a fault or abuse cannot run up an
  unbounded bill or flood a customer with texts.
- **Backups.** A weekly export, with password hashes and salts stripped out, so
  that a backup cannot be turned into a way of logging in as somebody.
- **Automatic deletion** of data past its retention period, run nightly, with
  the periods visible and changeable in the dashboard.
- **Content Security Policy** and related headers on every response.
- **A daily self-check** that alerts the owner when something that should be
  working is not.

The measures are reviewed as the system changes. This list is to be updated when
it stops being accurate — an out-of-date security schedule is a misrepresentation
in a signed contract, not a documentation problem.

---

## 6. Authorised sub-processors

Cousins authorises the following. Each is engaged because the system genuinely
cannot do its job without it, and each is named in the customer-facing privacy
notice, so this list and that page must be kept in step.

| Sub-processor | What it does | Data it sees | Where |
| --- | --- | --- | --- |
| Cloudflare, Inc. | Hosting and the booking database | All of it | UK/EU edge, US company |
| Resend (Plus Five Five, Inc.) | Sends confirmations and receipts | Name, email, job details | US |
| Twilio Inc. | Texts and calls about a job | Name, mobile, job details | US |
| Meta Platforms Ireland Ltd | WhatsApp job updates, where used | Mobile number, message content | EU/US |
| HubSpot, Inc. | Customer records; site analytics with consent | Name, email, phone, job history | EU data centre, US company |
| Google Ireland Ltd | The diary jobs are booked into; maps on the site | First name, postcode, job type, time | EU/US |
| UK Vehicle Data | Registration lookups | The registration only | UK |
| Postcodes.io | Turns a map pin into a postcode | Approximate location only | UK |

**SumUp is not a sub-processor.** SumUp Limited takes card payments into
Cousins' own merchant account. Because it is a regulated payment institution
with its own legal duties — anti-money-laundering checks, transaction
monitoring, records it must keep whatever Cousins says — SumUp decides its own
purposes for that data and acts as a **controller in its own right**, not on the
Supplier's instructions. Cousins' relationship with SumUp is therefore direct,
under SumUp's own terms, and the merchant account is in Cousins' name. The
Supplier never holds Cousins' takings and never sees a card number.

**Changes.** The Supplier shall give Cousins at least **30 days' written notice**
before adding or replacing a sub-processor. Cousins may object on reasonable
data-protection grounds, and if the objection cannot be resolved Cousins may
terminate the affected service without penalty.

**Liability.** The Supplier remains fully liable to Cousins for the performance
of each sub-processor's obligations.

---

## 7. International transfers

Several sub-processors are in the United States or transfer data there. Those
transfers rely on the **UK International Data Transfer Addendum to the EU
Standard Contractual Clauses**, or on the UK extension of the **EU–US Data
Privacy Framework** where the recipient is certified under it.

The Supplier shall not transfer personal data outside the UK except to the
sub-processors listed above, or to another with Cousins' written authorisation
and an appropriate safeguard under Article 46 in place.

Adequacy findings and framework certifications are withdrawn and challenged from
time to time. This section is to be checked when that happens rather than
assumed to hold — it has been unsettled more than once.

---

## 8. Audit

Cousins may audit the Supplier's compliance with this agreement **once in any
12-month period**, on 30 days' written notice, and additionally at any time
following a personal data breach.

The Supplier shall provide reasonable assistance, including access to relevant
documentation, security settings and processing records. Audits shall be
conducted during business hours and in a way that does not unreasonably disrupt
the Supplier's operations.

---

## 9. Deletion and return

On termination, or earlier if Cousins asks in writing, the Supplier shall at
Cousins' choice either return all personal data in a commonly used machine-
readable format, or delete it, and delete all existing copies.

**The data belongs to Cousins.** It is a garage's customer book. Nothing in this
agreement gives the Supplier any right to keep, reuse or repurpose it — including
for training, benchmarking, portfolio work, or as a starting point for another
client's system.

Where the law requires the Supplier to keep a copy, it shall tell Cousins which
data, on what legal basis, and for how long, and shall keep processing it only
to the extent that law requires.

The Supplier shall confirm deletion in writing within **30 days**.

---

## 10. Liability, term and general

**This is the section a solicitor should look at hardest.** The clauses below
are ordinary, middle-of-the-road positions offered so that the agreement can be
signed rather than left open. Either party may strike or change any of them
before signing. Amend the numbers to what you actually agree.

**10.1 Term and notice.** This agreement runs from the date of signature for as
long as the Supplier processes personal data for Cousins. Either party may end
it on `[30 / 60 / 90]` days' written notice. During the notice period the
Supplier shall keep the site and booking system running normally, and shall not
withhold service, data or access over a commercial dispute.

**10.2 Liability.** Each party's liability to the other under this agreement is
capped at `[the total fees paid by Cousins to the Supplier in the 12 months
before the claim / £____]`. Nothing in this agreement limits liability for death
or personal injury caused by negligence, for fraud, or for anything else that
cannot lawfully be limited. **A cap between the parties does not limit what the
ICO may fine either party directly** — the ICO is not bound by private contract.

**10.3 Insurance.** The Supplier `[does / does not]` carry professional
indemnity and cyber insurance at `[£____]`. If it does, it shall maintain that
cover for the term and provide evidence on request. *Note: if the answer is "does
not", say so honestly here rather than leaving it blank. Cousins is entitled to
know, and a false statement in a signed contract is a worse problem than no
cover.*

**10.4 Business continuity — the clause that matters most.** This is a practical
risk, not a legal one, and it is the likeliest of anything here to actually hurt
Cousins. The Supplier shall ensure that Cousins is able to regain sole control
of its own business if the Supplier becomes unavailable for any reason. In
particular:

- Cousins holds, or can obtain within `[5]` working days, administrative access
  to the domain `cousinsmechanicalservices.co.uk` and to the hosting account.
- Cousins' own accounts — Google, SumUp, HubSpot — are registered in Cousins'
  name and remain accessible to Cousins independently of the Supplier.
- At least one Cousins-held login to the dashboard carries the **owner** role at
  all times, and it is not the Supplier's account.
- The Supplier provides a current data export on request, and in any event on
  termination, under section 9.

**10.5 Governing law.** This agreement is governed by the law of England and
Wales, and the courts of England and Wales have exclusive jurisdiction.

**10.6 Whole agreement.** This agreement covers data protection. Where it
conflicts with any other agreement between the parties on the handling of
personal data, this one prevails.

---

## Signatures

**For Cousins Mechanical Services Ltd (Controller)**

Name: `[  ]`  Position: `[  ]`  Signature: `[  ]`  Date: `[  ]`

**For `[SUPPLIER LEGAL NAME]` (Processor)**

Name: `[  ]`  Position: `[  ]`  Signature: `[  ]`  Date: `[  ]`

---

*Version 1.0. Review when a sub-processor changes, when the security measures in
section 5 change, or annually — whichever comes first.*

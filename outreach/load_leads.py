"""Load Charlotte, NC leads and email templates into the CRM."""

from . import database as db


# Pre-built leads from research
CHARLOTTE_LEADS = [
    # MSPs (white-label partners)
    {"company": "Stratify IT", "industry": "IT Services", "category": "msp", "priority": "high",
     "size": "30-80 employees", "website": "stratifyit.tech",
     "notes": "500+ clients in regulated industries (finance, legal, healthcare). SAM registered. Top MSP target."},
    {"company": "WorkSmart", "industry": "IT Services", "category": "msp", "priority": "high",
     "size": "50-150 employees", "website": "worksmart.com",
     "notes": "Multi-state MSP (Charlotte, Greensboro, Atlanta, Philly, NY). Large SMB client base."},
    {"company": "T3 MSP", "industry": "IT Services", "category": "msp", "priority": "high",
     "size": "20-50 employees", "website": "t3managedit.com",
     "notes": "500+ clients in healthcare, construction, logistics, legal. Charlotte and Atlanta."},
    {"company": "Complete Network", "industry": "IT Services", "category": "msp", "priority": "high",
     "size": "Mid-size", "website": "complete.network",
     "notes": "Inc 5000 four consecutive years. Fast-growing. Needs pentest partners."},
    {"company": "CorpInfoTech", "industry": "IT Services", "category": "msp", "priority": "high",
     "size": "15-40 employees", "website": "corp-infotech.com",
     "notes": "CMMC Level 2 certified, Cyber AB RPO. Government/defense clients need pentests."},
    {"company": "BlueArmor", "industry": "IT Services", "category": "msp", "priority": "medium",
     "size": "2-10 employees", "website": "bluearmor-us.com",
     "notes": "Small MSSP focused on construction. Defensive only -- needs offensive partner. 100% retention."},
    {"company": "SpectrumWise", "industry": "IT Services", "category": "msp", "priority": "medium",
     "size": "20-50 employees", "website": "spectrumwise.com",
     "notes": "20+ years in Charlotte. Healthcare IT focus. White-label opportunity."},
    {"company": "NXT GEN Managed IT", "industry": "IT Services", "category": "msp", "priority": "medium",
     "size": "5-20 employees", "website": "nxtgenmanagedit.com",
     "notes": "Veteran-owned. HIPAA compliance focus. Healthcare clients need pentests."},
    {"company": "Nexcom MSP", "industry": "IT Services", "category": "msp", "priority": "medium",
     "size": "38 employees", "website": "nexcommsp.com",
     "notes": "Construction/field service specialization. AWS deployment for 100+ companies."},

    # Healthcare
    {"company": "Tryon Medical Partners", "industry": "Healthcare", "category": "healthcare", "priority": "high",
     "size": "65-70 physicians, 9 locations", "website": "tryonmed.com",
     "notes": "Independent multi-specialty group. 2026 HIPAA pentest mandate applies."},
    {"company": "OrthoCarolina", "industry": "Healthcare", "category": "healthcare", "priority": "high",
     "size": "1,600 employees, 71 locations", "website": "orthocarolina.com",
     "notes": "Largest independent orthopedic practice. PACS/DICOM imaging. Massive attack surface."},
    {"company": "Friendly Dental Group", "industry": "Healthcare", "category": "healthcare", "priority": "high",
     "size": "200-500 employees, 28 locations", "website": "friendlydentalgroup.com",
     "notes": "Largest dental group in Carolinas. Digital imaging + PCI overlap."},
    {"company": "Amity Medical Group", "industry": "Healthcare", "category": "healthcare", "priority": "high",
     "size": "4 locations", "website": "amitymed.org",
     "notes": "HIV/addiction care -- extremely sensitive PHI. HIPAA + 42 CFR Part 2."},
    {"company": "HopeWay", "industry": "Healthcare", "category": "healthcare", "priority": "medium",
     "size": "52K sq ft facility", "website": "hopeway.org",
     "notes": "Behavioral health nonprofit. Mental health + eating disorder records. High sensitivity."},

    # Fintech / Finance
    {"company": "Infinant", "industry": "Fintech", "category": "fintech", "priority": "high",
     "size": "36 employees", "website": "infinant.com",
     "notes": "Banking-as-a-Service platform. Bank regulators require vendor pentests. SOC 2 needed."},
    {"company": "Tradier", "industry": "Fintech", "category": "fintech", "priority": "high",
     "size": "11-50 employees", "website": "tradier.com",
     "notes": "SEC/FINRA regulated brokerage API. Must demonstrate pentest compliance."},
    {"company": "Finzly", "industry": "Fintech", "category": "fintech", "priority": "high",
     "size": "Growing", "website": "finzly.com",
     "notes": "Payment processing -- ACH, Fedwire, RTP, FedNow, SWIFT. PCI-DSS mandatory."},
    {"company": "Skyla Credit Union", "industry": "Finance", "category": "fintech", "priority": "high",
     "size": "$1.6B assets, 112K members", "website": "skylacu.com",
     "notes": "Post-merger of Charlotte Metro + Premier Federal. NCUA/FFIEC compliance."},
    {"company": "Wyndham Capital Mortgage", "industry": "Finance", "category": "fintech", "priority": "high",
     "size": "200-800 employees", "website": "wyndhamcapital.com",
     "notes": "Mortgage lender in 47 states. GLBA Safeguards Rule requires pentesting."},
    {"company": "GreerWalker CPAs", "industry": "Accounting", "category": "fintech", "priority": "medium",
     "size": "120-147 employees", "website": "greerwalker.com",
     "notes": "Top 150 US CPA firm. IRS WISP requirement. Handles massive client financial data."},

    # Law Firms
    {"company": "Johnston, Allison & Hord", "industry": "Legal", "category": "legal", "priority": "medium",
     "size": "55+ attorneys", "website": "jahlaw.com",
     "notes": "Est. 1912. Real estate closings = wire fraud target. NC Bar data protection rules."},

    # Other
    {"company": "Foundation For The Carolinas", "industry": "Nonprofit", "category": "nonprofit", "priority": "medium",
     "size": "$2.7B assets, 600+ nonprofits", "website": "fftc.org",
     "notes": "Manages $2.7B. Connects 600+ nonprofits. Gateway to entire nonprofit ecosystem."},
    {"company": "Piedmont Plastics", "industry": "Manufacturing", "category": "manufacturing", "priority": "medium",
     "size": "600+ employees, 45+ branches", "website": "piedmontplastics.com",
     "notes": "Distributed manufacturing. OT/IT convergence. Supply chain security needs."},
    {"company": "Henderson Properties", "industry": "Real Estate", "category": "real_estate", "priority": "medium",
     "size": "35+ years", "website": "hendersonproperties.com",
     "notes": "Property management. Tenant PII, wire fraud risk. Data breach notification obligations."},
]


# Email templates keyed by company name
EMAIL_TEMPLATES = {
    "Stratify IT": (
        "Pentest partner for your regulated clients -- Charlotte based",
        """Hi,

I'm {sender_name} with {sender_company}, a cybersecurity assessment firm based here in Charlotte. I came across Stratify IT while researching the best MSPs in the area, and your work with financial services, legal, and healthcare clients caught my attention.

I'm reaching out because I know those regulated clients need penetration testing for PCI-DSS, HIPAA, SOC 2, and NIST compliance -- but most MSPs don't want to build an in-house offensive security team to deliver it. That's where I come in.

I'm looking for a few strong MSP partners in Charlotte to work with on a white-label basis:

- You sell the pentest to your clients as part of your security stack
- I deliver the assessment (external, internal, web app, cloud, wireless)
- You get a co-branded report with your logo -- your client sees it as your service
- You set the margin -- I charge you a wholesale rate, you mark it up

This means you can offer compliance-required pentesting to your 500+ clients without hiring a single security tester. Every client in a regulated industry becomes new revenue for you.

I'd love to buy you a coffee and walk through how this could work. Would you have 20 minutes this week or next?

Best,
{sender_name}
{sender_company}
{sender_phone}"""
    ),
    "WorkSmart": (
        "Adding pentest revenue to your Charlotte clients",
        """Hi,

I'm {sender_name}, a penetration testing consultant based in Charlotte. I run {sender_company} -- we specialize in security assessments for SMBs in regulated industries.

I noticed WorkSmart has offices across multiple states and serves a broad SMB client base. I'm betting at least some of your clients have asked about penetration testing for compliance -- or their auditors have told them they need one.

Rather than turning that work away or referring it out, I'd like to propose a partnership:

- I handle all pentest engagements for your clients (external, internal, web app, cloud)
- Reports are co-branded with your logo
- You keep a referral fee or set your own markup on my wholesale rate
- I never contact your clients directly -- everything flows through you

I've built an AI-assisted testing platform that lets me deliver enterprise-quality assessments faster and at a better price point than the big firms. Your clients get a thorough report with CVSS scoring, MITRE ATT&CK mapping, and a prioritized remediation roadmap.

Would a 15-minute call make sense to explore this?

Best,
{sender_name}
{sender_company}
{sender_phone}"""
    ),
    "T3 MSP": (
        "Cybersecurity assessments for your healthcare and legal clients",
        """Hi,

I'm {sender_name} with {sender_company} here in Charlotte. I specialize in penetration testing and compliance-driven security assessments.

I see T3 MSP works with healthcare, legal, and construction clients -- three industries that are all facing increasing cybersecurity compliance pressure right now:

- Healthcare: The 2026 HIPAA Security Rule update now explicitly mandates penetration testing and vulnerability scanning
- Legal: NC State Bar rules require "reasonable efforts" to protect client data, and cyber insurance carriers are requiring pentests before issuing policies
- Construction: Wire fraud targeting construction companies has surged

Your clients need these assessments, and I'd like to be the partner who delivers them for you. I work on a white-label basis -- co-branded reports with your logo, wholesale pricing, and I never go around you to contact your clients.

One assessment typically runs $3,000-$8,000 depending on scope. If even 10% of your 500+ client base needs an annual pentest, that's significant recurring revenue for both of us.

Worth a conversation?

Best,
{sender_name}
{sender_company}
{sender_phone}"""
    ),
    "Tryon Medical Partners": (
        "2026 HIPAA pentest requirement -- Tryon Medical Partners",
        """Hi,

I'm {sender_name} with {sender_company}, a cybersecurity assessment firm in Charlotte. I'm reaching out because the updated HIPAA Security Rule now explicitly requires penetration testing and vulnerability scanning for covered entities -- and the compliance deadline is approaching.

With 9 locations and 65+ physicians, Tryon Medical Partners has a network environment that HHS will expect to see regularly tested: multi-site connectivity, EHR access points, patient portals, and medical devices all fall under scope.

I specialize in healthcare security assessments designed to satisfy HIPAA requirements while giving your IT team practical, prioritized fixes. Here's what an engagement looks like:

- External and internal penetration test across your locations
- Web application assessment (patient portal, any public-facing apps)
- Wireless security assessment at select locations
- HIPAA-aligned report your compliance officer can present to auditors
- Prioritized remediation roadmap (30/60/90 day plan)
- Free retest of critical findings within 30 days

Would your IT director or practice administrator have 15 minutes for a brief call? I'm happy to provide a no-obligation scoping estimate.

Best,
{sender_name}
{sender_company}
{sender_phone}"""
    ),
    "Infinant": (
        "Pentest for Infinant's banking platform -- SOC 2 and regulator readiness",
        """Hi,

I'm {sender_name} with {sender_company}, a penetration testing firm in Charlotte. I specialize in security assessments for fintech companies, particularly those serving bank clients with embedded finance and BaaS platforms.

As a platform that enables banks to launch digital banking programs, Infinant sits at the intersection of multiple regulatory requirements: bank examiners expect your bank clients' vendors to have current penetration test reports, and SOC 2 Type II requires evidence of regular security testing.

At 36 employees, I'm guessing you don't have a dedicated offensive security team in-house -- and you shouldn't need one. That's what I do.

What I'd assess:

- API security testing of the Interlace platform (authentication, authorization, injection, business logic)
- Infrastructure penetration test (cloud environment, network segmentation)
- Authentication and session management review
- Data encryption validation (at rest and in transit)
- SOC 2 and bank examiner-ready report with full remediation guidance

Typical turnaround is 2-3 weeks from kickoff to final report. Would your CTO or Head of Engineering have 15 minutes to discuss scope?

Best,
{sender_name}
{sender_company}
{sender_phone}"""
    ),
    "Complete Network": (
        "Pentest partnership for your Inc 5000 clients -- Charlotte based",
        """Hi,

I'm {sender_name} with {sender_company}, a cybersecurity assessment firm here in Charlotte. Congrats on the Inc 5000 recognition four years running -- that kind of growth speaks volumes about the quality of service you deliver.

I'm reaching out because fast-growing MSPs like Complete Network often hit a point where clients start asking for penetration testing and compliance assessments -- especially in regulated industries. Building an in-house offensive security team is expensive, but turning that work away means lost revenue.

I'd like to propose a simple partnership:

- I deliver penetration tests for your clients (external, internal, web app, cloud, wireless)
- Reports are co-branded with your logo -- your client sees it as your service
- You set the margin on a wholesale rate
- I never contact your clients directly

This lets you add a high-margin security service to your stack without any new hires. Would a quick call make sense to explore this?

Best,
{sender_name}
{sender_company}
{sender_phone}"""
    ),
    "CorpInfoTech": (
        "Pentest delivery for your CMMC and government clients",
        """Hi,

I'm {sender_name} with {sender_company}, a penetration testing firm in Charlotte. I noticed CorpInfoTech holds CMMC Level 2 certification and is a Cyber AB RPO -- that tells me your clients take security seriously, and many of them likely need regular penetration testing to maintain compliance.

CMMC, NIST 800-171, and FedRAMP all require or strongly recommend penetration testing. Your government and defense clients need these assessments, and I'd like to be the partner who delivers them for you.

Here's what I bring to the table:

- NIST SP 800-115 aligned penetration testing methodology
- Assessments scoped to CMMC/NIST 800-171 control families
- Co-branded reports with your logo for white-label delivery
- Wholesale pricing so you can set your own margin

If even a handful of your defense contractor clients need an annual pentest at $5,000-$10,000 each, that's meaningful recurring revenue for both of us -- with zero new headcount on your end.

Worth a 15-minute conversation?

Best,
{sender_name}
{sender_company}
{sender_phone}"""
    ),
    "BlueArmor": (
        "Offensive security partner for BlueArmor's construction clients",
        """Hi,

I'm {sender_name} with {sender_company}, a penetration testing consultant here in Charlotte. I came across BlueArmor and was impressed by your 100% client retention -- that's rare in this industry and says a lot about the quality of your defensive security work.

I know as an MSSP focused on defense, you probably get asked about penetration testing from time to time. Wire fraud targeting construction companies has exploded, and insurance carriers are increasingly requiring pentests before issuing or renewing cyber policies.

Rather than building an offensive capability in-house, I'd like to offer a simple referral or white-label arrangement:

- Your clients get professional penetration tests from a local Charlotte firm
- You get a referral fee or markup on my wholesale rate
- Reports can be co-branded with BlueArmor's logo
- I never go around you -- everything flows through your relationship

This way you can say "yes" to the offensive security question without changing your core business. Would a quick coffee chat work?

Best,
{sender_name}
{sender_company}
{sender_phone}"""
    ),
    "SpectrumWise": (
        "Pentest partner for your healthcare clients -- Charlotte based",
        """Hi,

I'm {sender_name} with {sender_company}, a cybersecurity assessment firm here in Charlotte. With 20+ years serving the Charlotte market and a focus on healthcare IT, SpectrumWise is exactly the kind of MSP I'd love to partner with.

The 2026 HIPAA Security Rule update now explicitly mandates penetration testing for covered entities. That means your healthcare clients will need documented pentests -- and they'll likely look to you first for a solution.

I deliver HIPAA-aligned penetration tests on a white-label basis:

- External/internal network testing, web app assessments, wireless security
- HIPAA-specific reporting that your clients' compliance officers can present to auditors
- Co-branded reports with SpectrumWise's logo
- Wholesale pricing so you control the margin

Would 15 minutes work to explore how this could fit into your service offering?

Best,
{sender_name}
{sender_company}
{sender_phone}"""
    ),
    "NXT GEN Managed IT": (
        "HIPAA pentest delivery for your healthcare clients",
        """Hi,

I'm {sender_name} with {sender_company}, a penetration testing firm in Charlotte. First -- thank you for your service. I have a lot of respect for veteran-owned businesses.

I see NXT GEN focuses on HIPAA compliance for healthcare clients. With the 2026 HIPAA Security Rule update now explicitly requiring penetration testing, your clients will need documented assessments to stay compliant.

I'd like to offer a partnership where I handle the offensive security side:

- HIPAA-aligned penetration tests (network, web app, wireless)
- Reports formatted for compliance auditors and insurance carriers
- White-label delivery under your brand
- Wholesale pricing with your markup

This lets you offer a complete HIPAA compliance solution without building an in-house pentest team. Worth a quick call?

Best,
{sender_name}
{sender_company}
{sender_phone}"""
    ),
    "Nexcom MSP": (
        "Security assessments for your construction and AWS clients",
        """Hi,

I'm {sender_name} with {sender_company}, a penetration testing consultant in Charlotte. I noticed Nexcom specializes in construction and field service companies, with AWS deployments for 100+ clients -- that's a significant cloud footprint.

Two things I'm seeing in the market right now:

1. Construction companies are prime targets for wire fraud and ransomware -- insurance carriers are requiring pentests before issuing cyber policies
2. AWS environments need regular security assessments to validate configurations, IAM policies, and network segmentation

I deliver both on a white-label basis -- co-branded reports, wholesale pricing, and I work exclusively through your client relationship.

If even 10% of your 100+ clients need an annual cloud or network pentest, that's significant recurring revenue with zero new headcount. Worth a conversation?

Best,
{sender_name}
{sender_company}
{sender_phone}"""
    ),
    "OrthoCarolina": (
        "2026 HIPAA pentest requirement -- OrthoCarolina's 71 locations",
        """Hi,

I'm {sender_name} with {sender_company}, a cybersecurity assessment firm in Charlotte. I'm reaching out because the updated HIPAA Security Rule now explicitly requires penetration testing for covered entities -- and with 71 locations and 1,600 employees, OrthoCarolina has one of the largest independent healthcare networks in the region.

Your environment includes the kind of systems HHS will expect to see regularly tested: PACS/DICOM imaging systems, multi-site network connectivity, EHR platforms, patient portals, and connected medical devices.

Here's what a scoped engagement would look like:

- External penetration test of your internet-facing infrastructure
- Internal network assessment at representative locations
- Medical device and PACS/DICOM security review
- Web application testing (patient portal, scheduling systems)
- HIPAA-aligned report with prioritized remediation roadmap

I'm local here in Charlotte and specialize in healthcare security. Would your IT security team or CISO have 15 minutes for a scoping conversation?

Best,
{sender_name}
{sender_company}
{sender_phone}"""
    ),
    "Amity Medical Group": (
        "Security assessment for sensitive patient data -- HIPAA + 42 CFR Part 2",
        """Hi,

I'm {sender_name} with {sender_company}, a cybersecurity assessment firm in Charlotte. I specialize in healthcare security, and I'm reaching out because Amity Medical Group handles some of the most sensitive categories of protected health information -- substance abuse treatment and HIV care records.

These records carry additional federal protections under 42 CFR Part 2, on top of standard HIPAA requirements. The 2026 HIPAA Security Rule update now explicitly mandates penetration testing, and organizations handling Part 2 data face even higher scrutiny.

A targeted security assessment would cover:

- Network segmentation validation (ensuring Part 2 data is properly isolated)
- Access control and authentication review across your 4 locations
- EHR and patient portal security testing
- HIPAA + 42 CFR Part 2 aligned compliance report

I understand the sensitivity involved and maintain strict confidentiality protocols throughout every engagement. Would a brief call make sense to discuss scope?

Best,
{sender_name}
{sender_company}
{sender_phone}"""
    ),
    "Tradier": (
        "Penetration test for Tradier's brokerage API -- SEC/FINRA compliance",
        """Hi,

I'm {sender_name} with {sender_company}, a penetration testing firm in Charlotte specializing in fintech security assessments.

As a SEC/FINRA regulated brokerage platform with a public-facing trading API, Tradier sits squarely in the crosshairs of regulatory security requirements. FINRA Rule 3110 and SEC Regulation S-P both expect firms to demonstrate regular security testing of their systems.

Here's what I'd focus on:

- API security testing (authentication, authorization, rate limiting, business logic flaws)
- Infrastructure penetration test of your cloud environment
- Account takeover and session management testing
- Data handling review (PII, financial data, trading records)
- Regulatory-ready report suitable for SEC/FINRA examiner review

Typical turnaround is 2-3 weeks. Would your CTO or security lead have 15 minutes to discuss scope?

Best,
{sender_name}
{sender_company}
{sender_phone}"""
    ),
    "Finzly": (
        "PCI-DSS pentest for Finzly's payment processing platform",
        """Hi,

I'm {sender_name} with {sender_company}, a penetration testing firm in Charlotte. I specialize in security assessments for payment processing and fintech companies.

Finzly's platform touches some of the most critical payment rails in the US -- ACH, Fedwire, RTP, FedNow, and SWIFT. That means PCI-DSS compliance is mandatory, and PCI Requirement 11.3 explicitly requires annual penetration testing by a qualified assessor.

What I'd assess:

- External and internal penetration testing per PCI-DSS 11.3
- Payment API security testing (injection, authentication, business logic)
- Network segmentation validation between cardholder data environments
- Cloud infrastructure security review
- PCI-DSS compliant report with ASV-ready documentation

I deliver assessments that satisfy both PCI auditors and bank examiners. Would your engineering or security team have 15 minutes for a scoping call?

Best,
{sender_name}
{sender_company}
{sender_phone}"""
    ),
    "Skyla Credit Union": (
        "NCUA/FFIEC penetration test -- Skyla Credit Union",
        """Hi,

I'm {sender_name} with {sender_company}, a cybersecurity assessment firm in Charlotte. Congratulations on the successful merger of Charlotte Metro and Premier Federal -- building Skyla into a $1.6B institution serving 112,000 members is impressive.

Post-merger is actually one of the most critical times for a security assessment. Merging two separate IT environments creates new attack surface, and NCUA examiners and the FFIEC IT Examination Handbook both expect credit unions to conduct regular penetration testing.

Here's what I'd recommend:

- External penetration test of merged internet-facing infrastructure
- Internal network assessment validating segmentation between legacy environments
- Online banking and member portal security testing
- Social engineering assessment (phishing simulation for staff)
- FFIEC-aligned report your examiner can review directly

I'm local here in Charlotte and can work within your examination timeline. Would your IT security team have 15 minutes to discuss scope?

Best,
{sender_name}
{sender_company}
{sender_phone}"""
    ),
    "Wyndham Capital Mortgage": (
        "GLBA Safeguards Rule pentest -- Wyndham Capital Mortgage",
        """Hi,

I'm {sender_name} with {sender_company}, a penetration testing firm here in Charlotte. I specialize in security assessments for financial services companies.

As a mortgage lender operating in 47 states, Wyndham Capital falls under the FTC's updated GLBA Safeguards Rule, which now requires regular penetration testing and vulnerability assessments as part of your information security program.

With 200-800 employees handling sensitive borrower data -- SSNs, financial statements, tax returns, bank accounts -- the attack surface is significant, and regulators expect documented evidence of security testing.

What I'd assess:

- External and internal penetration testing
- Web application security (loan origination portal, borrower-facing apps)
- Social engineering assessment (phishing simulation)
- Cloud and infrastructure security review
- GLBA Safeguards Rule compliant report

Would your CISO or IT security team have 15 minutes for a scoping conversation?

Best,
{sender_name}
{sender_company}
{sender_phone}"""
    ),
}


def get_email_for_lead(lead: dict) -> tuple:
    """Get personalized email subject and body for a lead. Returns (subject, body) or (None, None)."""
    template = EMAIL_TEMPLATES.get(lead.get("company"))
    if not template:
        return None, None

    subject, body_template = template
    sender_name = db.get_setting("display_name", "[YOUR NAME]")
    sender_company = db.get_setting("company_name", "[YOUR COMPANY]")
    sender_phone = db.get_setting("phone", "[YOUR PHONE]")

    body = body_template.format(
        sender_name=sender_name,
        sender_company=sender_company,
        sender_phone=sender_phone,
    )
    return subject, body


def load_charlotte_leads() -> int:
    """Load all Charlotte leads into the database. Returns count loaded."""
    db.init_db()
    count = 0

    # Check for existing leads to avoid duplicates
    existing = {l["company"] for l in db.list_leads()}

    for lead_data in CHARLOTTE_LEADS:
        if lead_data["company"] in existing:
            continue

        db.add_lead(
            company=lead_data["company"],
            industry=lead_data.get("industry", ""),
            category=lead_data.get("category", ""),
            priority=lead_data.get("priority", "medium"),
            size=lead_data.get("size", ""),
            website=lead_data.get("website", ""),
            notes=lead_data.get("notes", ""),
            source="charlotte_research",
        )
        count += 1

    return count

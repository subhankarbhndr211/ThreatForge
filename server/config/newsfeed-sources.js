// config/newsfeed-sources.js
const RSS_FEEDS = [
    // Major Security Blogs
    { name: 'KrebsOnSecurity', url: 'https://krebsonsecurity.com/feed/', category: 'blog' },
    { name: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews', category: 'news' },
    { name: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed/', category: 'news' },
    { name: 'SecurityWeek', url: 'https://feeds.feedburner.com/securityweek', category: 'news' },
    { name: 'Dark Reading', url: 'https://www.darkreading.com/rss.xml', category: 'news' },
    
    // Vendor Research Blogs
    { name: 'Cisco Talos', url: 'https://blog.talosintelligence.com/rss/', category: 'research' },
    { name: 'Palo Alto Unit 42', url: 'https://unit42.paloaltonetworks.com/feed/', category: 'research' },
    { name: 'Microsoft Security', url: 'https://www.microsoft.com/en-us/security/blog/feed/', category: 'research' },
    { name: 'CrowdStrike', url: 'https://www.crowdstrike.com/en-us/blog/feed', category: 'research' },
    { name: 'Securelist (Kaspersky)', url: 'https://securelist.com/feed/', category: 'research' },
    { name: 'SentinelLabs', url: 'https://www.sentinelone.com/labs/feed/', category: 'research' },
    { name: 'Check Point Research', url: 'https://research.checkpoint.com/feed/', category: 'research' },
    { name: 'Mandiant', url: 'https://www.mandiant.com/resources/blog/rss.xml', category: 'research' },
    { name: 'Fortinet', url: 'https://www.fortinet.com/rss-feeds', category: 'research' },
    { name: 'Rapid7', url: 'https://www.rapid7.com/rss.xml', category: 'research' },
    { name: 'Trend Micro', url: 'http://feeds.trendmicro.com/TrendMicroSimplySecurity', category: 'research' },
    { name: 'Sophos', url: 'https://news.sophos.com/en-us/category/threat-research/feed/', category: 'research' },
    { name: 'McAfee Labs', url: 'https://www.mcafee.com/blogs/other-blogs/mcafee-labs/feed/', category: 'research' },
    { name: 'Symantec', url: 'https://sed-cms.broadcom.com/rss/v1/blogs/rss.xml', category: 'research' },
    { name: 'Zscaler', url: 'https://www.zscaler.com/blogs/feeds/security-research', category: 'research' },
    { name: 'Cloudflare', url: 'https://blog.cloudflare.com/rss/', category: 'research' },
    { name: 'Akamai', url: 'https://www.akamai.com/blog/feed', category: 'research' },
    { name: 'AWS Security', url: 'https://aws.amazon.com/blogs/security/feed/', category: 'research' },
    { name: 'Google Cloud', url: 'https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/', category: 'research' },
    
    // DFIR & Threat Intel
    { name: 'The DFIR Report', url: 'https://thedfirreport.com/feed/', category: 'dfir' },
    { name: 'SANS ISC', url: 'https://isc.sans.edu/rssfeed.xml', category: 'dfir' },
    { name: 'Volexity', url: 'https://www.volexity.com/feed/', category: 'threat-intel' },
    { name: 'Recorded Future', url: 'https://www.recordedfuture.com/feed', category: 'threat-intel' },
    { name: 'ThreatPost', url: 'https://threatpost.com/feed/', category: 'news' },
    { name: 'GBHackers', url: 'https://gbhackers.com/feed/', category: 'news' },
    { name: 'Cyber Security News', url: 'https://cybersecuritynews.com/feed/', category: 'news' },
    { name: 'Security Affairs', url: 'https://securityaffairs.com/feed', category: 'news' },
    { name: 'Help Net Security', url: 'https://www.helpnetsecurity.com/view/news/feed/', category: 'news' },
    
    // Malware Analysis
    { name: 'Malwarebytes', url: 'https://www.malwarebytes.com/blog/feed/index.xml', category: 'malware' },
    { name: 'Intezer', url: 'https://intezer.com/feed/', category: 'malware' },
    { name: 'Cybereason', url: 'https://www.cybereason.com/blog/rss.xml', category: 'malware' },
    { name: 'Bitdefender', url: 'https://www.bitdefender.com/nuxt/api/en-us/rss/labs/', category: 'malware' },
    
    // Additional Sources
    { name: 'WeLiveSecurity (ESET)', url: 'https://www.welivesecurity.com/en/rss/feed/', category: 'research' },
    { name: 'Cofense', url: 'https://cofense.com/feed', category: 'phishing' },
    { name: 'PhishLabs', url: 'https://www.phishlabs.com/feed', category: 'phishing' },
    { name: 'SOCRadar', url: 'https://socradar.io/feed/', category: 'threat-intel' },
    { name: 'Cyble', url: 'https://cyble.com/feed/', category: 'threat-intel' },
    { name: 'EclecticIQ', url: 'https://blog.eclecticiq.com/rss.xml', category: 'threat-intel' },
    { name: 'Group-IB', url: 'https://www.group-ib.com/feed/blogfeed/', category: 'research' },
    { name: 'Sekoia', url: 'https://blog.sekoia.io/feed/', category: 'threat-intel' },
    { name: 'Silent Push', url: 'https://www.silentpush.com/feed/', category: 'threat-intel' },
    { name: 'Wiz', url: 'https://www.wiz.io/api/feed/cloud-threat-landscape/rss.xml', category: 'cloud' },
    { name: 'Permiso', url: 'https://permiso.io/blog/rss.xml', category: 'cloud' }
];

const REDDIT_SUBREDDITS = [
    { name: 'r/netsec', url: 'https://www.reddit.com/r/netsec/.rss', category: 'reddit' },
    { name: 'r/cybersecurity', url: 'https://www.reddit.com/r/cybersecurity/.rss', category: 'reddit' },
    { name: 'r/blueteamsec', url: 'https://www.reddit.com/r/blueteamsec/.rss', category: 'reddit' },
    { name: 'r/blackhat', url: 'https://www.reddit.com/r/blackhat/.rss', category: 'reddit' },
    { name: 'r/HowToHack', url: 'https://www.reddit.com/r/HowToHack/.rss', category: 'reddit' },
    { name: 'r/TryHackMe', url: 'https://www.reddit.com/r/TryHackMe/.rss', category: 'reddit' },
    { name: 'r/securityCTF', url: 'https://www.reddit.com/r/securityCTF/.rss', category: 'reddit' },
    { name: 'r/malware', url: 'https://www.reddit.com/r/malware/.rss', category: 'reddit' },
    { name: 'r/ReverseEngineering', url: 'https://www.reddit.com/r/ReverseEngineering/.rss', category: 'reddit' }
];

module.exports = { RSS_FEEDS, REDDIT_SUBREDDITS };
const SPAM_KEYWORDS = {
    high: [
        "free money", "claim now", "act now", "urgent", "congratulations",
        "you've been selected", "winner", "lottery", "prince", "inheritance",
        "million dollars", "cash prize", "click here", "buy now",
        "order now", "risk free", "no obligation", "guaranteed",
        "credit card", "social security", "bank account", "password",
        "verify your account", "account suspended", "limited time",
        "earn money", "work from home", "make money fast",
        "nigerian prince", "wire transfer", "western union",
        "bitcoin", "crypto investment", "double your money",
        "unlimited income", "no credit check", "apply now",
        "dear friend", "dear sir", "dear madam", "beloved",
        "god given", "divine", "million usd", "fund transfer",
        "confidential business", "stranger", "benevolent",
        "assistance", "partnership", "mutual benefit"
    ],
    medium: [
        "free", "discount", "offer", "save", "cheap", "buy",
        "sale", "special", "promo", "coupon", "deal", "bargain",
        "lowest price", "best price", "clearance", "rebate",
        "subscribe", "unsubscribe", "newsletter", "marketing",
        "investment", "profit", "income", "revenue", "earn",
        "opportunity", "business", "entrepreneur", "success",
        "weight loss", "diet", "pills", "medicine", "doctor",
        "miracle", "amazing", "incredible", "unbelievable",
        "viagra", "cialis", "pharmacy", "health", "supplement",
        "casino", "gambling", "bet", "poker", "jackpot",
        "dating", "singles", "meet", "romance", "love",
        "degree", "diploma", "certificate", "education",
        "refinance", "loan", "mortgage", "credit", "debt"
    ]
};
const SUSPICIOUS_PATTERNS = [
    { pattern: /\d{5,}@/, description: "Email contains many numbers" },
    { pattern: /@(free|cheap|promo|deal|spam|temp|fake|test)\./i, description: "Suspicious email domain" },
    { pattern: /no-?reply@|noreply@|donotreply@/i, description: "No-reply sender address" },
    { pattern: /@.*\.(ru|cn|ng|gh|in|pk|bd)$/, description: "High-risk country domain" },
    { pattern: /^[a-z]{1,3}\d+@/i, description: "Random-looking email address" },
    { pattern: /@(gmail|yahoo|hotmail)\.com\./i, description: "Fake popular email domain" },
    { pattern: /@.*-.*-.*\./i, description: "Multiple hyphens in domain" }
];

let stats ={ totalChecked: 0,
    totalSpam:0,
    totalClean:0
};

let history =[];

function analyzeEmail(){
    const senderEmail = document.getElementById('senderEmail').value.trim();
    const subjectLine = document.getElementById('subjectLine').value.trim();
    const emailBody = document.getElementById('emailBody').value.trim();

    if(!senderEmail && ! subjectLine && !emailBody){
        showNotification("Please enter some email content to analyze!","warning");
        return;
    }

    const fullText = `${subjectLine} ${emailBody}`.toLowerCase();
    let spamScore = 0;
    let findings = [];
    let foundKeywords = [];
    let recommendations = [];

    const keywordResults = checkKeywords(fullText);
    spamScore += keywordResults.score;
    findings = findings.concat(keywordResults.findings);
    foundKeywords = foundKeywords.concat(keywordResults.keywords);

    if(senderEmail){
        const senderResult = checkSenderEmail(senderEmail);
        spamScore +=senderResult.score;
        findings = findings.concat(senderResult.findings);
    }

    if(subjectLine){
        const subjectResults= checkSubjectLine(subjectLine);
        spamScore +=subjectResults.score;
        findings = findings.concat(subjectResults.findings);
        foundKeywords = foundKeywords.concat(subjectResults.keywords);
    }

    const punctResults = checkPunctuation(fullText);
    spamScore +=punctResults.score;
    findings = findings.concat(punctResults.findings);

    const capsResults = checkAllCaps(emailBody);
    spamScore +=capsResults.score;
    findings = findings.concat(capsResults.findings);

    const urlResults = checkURLs(fullText);
    spamScore +=urlResults.score;
    findings = findings.concat(urlResults.findings);

    const phraseResults = checkSuspiciousPhrases(fullText);
    spamScore += phraseResults.score;
    findings = findings.concat(phraseResults.findings);

    const lengthResults = checkEmailLength(emailBody);
    spamScore +=lengthResults.score;
    findings = findings.concat(lengthResults.findings);

    spamScore = Math.min(spamScore, 100);

    displayResults(spamScore,findings, foundKeywords, recommendations);

    stats.totalChecked++;
    if(spamScore>=60){
        stats.totalSpam++;
    }else{
        stats.totalClean++;
    }
    updateStats();

    addToHistory(senderEmail, subjectLine, spamScore);

    if (spamScore >= 60) {
        showNotification("🚨 SPAM DETECTED! This email is likely spam.", "danger");
    } else if (spamScore >= 35) {
        showNotification("⚠️ SUSPICIOUS! This email needs careful review.", "warning");
    } else {
        showNotification("✅ SAFE! This email appears to be legitimate.", "success");
    }
}

function checkKeywords(text){
    let score = 0;
    let findings = [];
    let keywords = [];

    SPAM_KEYWORDS.high.forEach(keyword=> {
        const regex = new RegExp(`\\b${keyword}\\b`, 'gi');
        const matches = text.match(regex);
        if(matches){
            score += 8 * matches.length;
            keywords.push({word: keyword, level:'high'});
            if(matches.length === 1){
                findings.push({
                    level:'high',
                    icon: '🔴',
                    title: `High-risk keyword: "${keyword}"`,
                    detail: `Found ${matches.length} time(s) — strong spam indicator`
                });
            }
        }
    });

    SPAM_KEYWORDS.medium.forEach(keyword=> {
        const regex = new RegExp(`\\b${keyword}\\b`, 'gi');
        const matches = text.match(regex);
        if(matches){
            score += 3 * matches.length;
            keywords.push({word: keyword, level:'medium'});
        }
    });

    if (keywords.filter(k => k.level === 'medium').length > 5) {
        findings.push({
            level: 'medium',
            icon: '🟡',
            title: `Multiple spam-related words found`,
            detail: `${keywords.filter(k => k.level === 'medium').length} medium-risk keywords detected`
        });
    }
    return{ score, findings, keywords};
}
function checkSenderEmail(email){
    let score = 0;
    let findings =[];

    SUSPICIOUS_PATTERNS.forEach(({ pattern, description }) => {
        if (pattern.test(email)) {
            score += 10;
            findings.push({
                level: 'high',
                icon: '📧',
                title: `Suspicious sender pattern`,
                detail: `${description}: ${email}`
            });
        }
    });

    if (email.length > 50) {
        score += 5;
        findings.push({
            level: 'low',
            icon: '📏',
            title: 'Unusually long email address',
            detail: `Length: ${email.length} characters`
        });
    }

    if ((email.match(/@/g) || []).length > 1) {
        score += 15;
        findings.push({
            level: 'high',
            icon: '❌',
            title: 'Multiple @ symbols in email',
            detail: 'This is an invalid email format'
        });
    }
    return{score, findings};
}
function checkSubjectLine(subject){
    let score = 0;
    let findings = [];
    let keywords = [];
    const exclamations = (subject.match(/!/g) || []).length;
if(exclamations >= 10) {
    findings.push({
        level:'medium',
        icon: '‼️',
        title:`${exclamations} exclamation marks in subject`,
        detail: 'Excessive punctuation is a common spam tactic'
    });
}
const words = subject.split(/\s+/);
const capsWords = words.filter(w => w.length > 3 && w === w.toUpperCase());
if(capsWords.length > 2){
    score += 8;
    findings.push({
        level:'medium',
        icon: '🔠',
        title:'Multiple ALL-CAPS words in subject',
        detail: `"${capsWords.join(',')}" - shouting style is suspicious`
    });
}

const dollarPattern = /\$\s*\d{1,3}(?:,\d{3})*(?:\.\d{2})?/g;
const dollars = subject.match(dollarPattern);
if(dollars){
    score +=12;
    findings.push({
        level:'high',
        icon: '💰',
        title: `Money amount in subject: ${dollars.join(', ')}`,
        detail: 'Promising money in subject line is a strong spam signal'
    });
}
 SPAM_KEYWORDS.high.forEach(keyword => {
        if (subject.toLowerCase().includes(keyword)) {
            score += 5;
            keywords.push({ word: keyword, level: 'high' });
        }
    });

    return { score, findings, keywords };
}
function checkPunctuation(text) {
    let score = 0;
    let findings = [];

    // Excessive exclamation marks
    const exclamations = (text.match(/!/g) || []).length;
    if (exclamations >= 5) {
        score += 8;
        findings.push({
            level: 'medium',
            icon: '‼️',
            title: `${exclamations} exclamation marks in email`,
            detail: 'Excessive exclamation marks suggest spam'
        });
    }

    // Excessive question marks
    const questions = (text.match(/\?/g) || []).length;
    if (questions >= 5) {
        score += 5;
        findings.push({
            level: 'low',
            icon: '❓',
            title: `${questions} question marks in email`,
            detail: 'Many question marks can indicate spam'
        });
    }

    // Multiple dollar signs
    const dollars = (text.match(/\$/g) || []).length;
    if (dollars >= 3) {
        score += 7;
        findings.push({
            level: 'medium',
            icon: '💲',
            title: `${dollars} dollar signs in email`,
            detail: 'Frequent money references are suspicious'
        });
    }

    return { score, findings };
}

function checkAllCaps(text) {
    let score = 0;
    let findings = [];

    if (!text) return { score, findings };

    const words = text.split(/\s+/).filter(w => w.length > 0);
    const capsWords = words.filter(w => w.length > 3 && w === w.toUpperCase() && /[A-Z]/.test(w));
    const capsRatio = capsWords.length / words.length;

    if (capsRatio > 0.3 && capsWords.length > 3) {
        score += 12;
        findings.push({
            level: 'high',
            icon: '🔠',
            title: `${Math.round(capsRatio * 100)}% of text is in ALL CAPS`,
            detail: `Words like "${capsWords.slice(0, 3).join(', ')}" — typical spam behavior`
        });
    } else if (capsRatio > 0.15 && capsWords.length > 2) {
        score += 5;
        findings.push({
            level: 'medium',
            icon: '🔡',
            title: 'Notable amount of ALL CAPS text',
            detail: `${capsWords.length} words in all caps`
        });
    }

    return { score, findings };
}

function checkURLs(text) {
    let score = 0;
    let findings = [];

    // Count URLs
    const urlPattern = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi;
    const urls = text.match(urlPattern) || [];

    if (urls.length >= 3) {
        score += 8;
        findings.push({
            level: 'medium',
            icon: '🔗',
            title: `${urls.length} links found in email`,
            detail: 'Multiple links can indicate phishing attempts'
        });
    }

    // Check for URL shorteners
    const shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'is.gd', 'buff.ly', 'ow.ly'];
    urls.forEach(url => {
        shorteners.forEach(shortener => {
            if (url.includes(shortener)) {
                score += 10;
                findings.push({
                    level: 'high',
                    icon: '🔗',
                    title: 'URL shortener detected',
                    detail: `Shortened URL: ${url} — hides the real destination`
                });
            }
        });
    });

    // IP address URLs
    const ipPattern = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/gi;
    if (ipPattern.test(text)) {
        score += 15;
        findings.push({
            level: 'high',
            icon: '🚨',
            title: 'IP address used as URL',
            detail: 'Legitimate emails rarely use IP addresses as links'
        });
    }

    // Click here patterns
    if (/click\s*(here|this|below|link)/gi.test(text)) {
        score += 7;
        findings.push({
            level: 'medium',
            icon: '👆',
            title: '"Click here" type language detected',
            detail: 'Common phishing tactic to drive clicks'
        });
    }

    return { score, findings };
}

function checkSuspiciousPhrases(text) {
    let score = 0;
    let findings = [];

    const suspiciousPhrases = [
        { phrase: /dear\s+(friend|sir|madam|beloved|one)/gi, name: "Generic greeting", points: 8 },
        { phrase: /you\s+(have|are)\s+(been\s+)?(selected|chosen|won)/gi, name: "You've been selected", points: 12 },
        { phrase: /congratulations.*won/gi, name: "Congratulations + winning", points: 15 },
        { phrase: /act\s+now.*limited/gi, name: "Urgency + scarcity", points: 10 },
        { phrase: /no\s+(cost|charge|obligation|fees)/gi, name: "No cost/obligation claims", points: 8 },
        { phrase: /100%\s*(free|guaranteed|satisfied)/gi, name: "100% claims", points: 7 },
        { phrase: /risk[\s-]*free/gi, name: "Risk-free claims", points: 7 },
        { phrase: /call\s+now|call\s+today/gi, name: "Call now pressure", points: 6 },
        { phrase: /do\s+not\s+(share|tell|delete)/gi, name: "Secrecy request", points: 10 },
        { phrase: /nigerian|african\s+prince/gi, name: "Nigerian prince scam", points: 20 },
        { phrase: /wire\s+transfer|western\s+union/gi, name: "Money transfer request", points: 15 },
        { phrase: /confidential.*business/gi, name: "Confidential business", points: 8 },
        { phrase: /reply.*with.*personal/gi, name: "Requesting personal info", points: 12 },
        { phrase: /verify.*account|account.*suspended|account.*locked/gi, name: "Account threat", points: 15 },
        { phrase: /claim.*prize|prize.*claim/gi, name: "Prize claim", points: 12 },
        { phrase: /earn.*\$\d+|make.*\$\d+/gi, name: "Money earning promise", points: 10 }
    ];

    suspiciousPhrases.forEach(({ phrase, name, points }) => {
        if (phrase.test(text)) {
            score += points;
            findings.push({
                level: points >= 12 ? 'high' : 'medium',
                icon: points >= 12 ? '🔴' : '🟡',
                title: `Suspicious phrase: "${name}"`,
                detail: `This pattern is commonly found in spam emails (+${points} points)`
            });
        }
    });

    return { score, findings };
}

function checkEmailLength(text) {
    let score = 0;
    let findings = [];

    if (!text) return { score, findings };

    // Very short emails with spam keywords
    if (text.length < 50 && text.length > 0) {
        const hasSpamWord = SPAM_KEYWORDS.high.some(kw => text.toLowerCase().includes(kw));
        if (hasSpamWord) {
            score += 5;
            findings.push({
                level: 'low',
                icon: '📝',
                title: 'Very short email with spam content',
                detail: 'Short emails packed with spam keywords are suspicious'
            });
        }
    }

    return { score, findings };
}

 
function displayResults(score, findings, keywords, recommendations) {
    const resultSection = document.getElementById('resultSection');
    resultSection.style.display = 'block';

    // Animate score
    const scoreCircle = document.getElementById('scoreCircle');
    const scoreValue = document.getElementById('scoreValue');
    const verdictIcon = document.getElementById('verdictIcon');
    const verdictText = document.getElementById('verdictText');

    // Determine category
    let category, categoryClass, icon, text;
    if (score >= 60) {
        category = 'danger';
        categoryClass = 'danger';
        icon = '🚨';
        text = 'SPAM DETECTED';
    } else if (score >= 35) {
        category = 'warning';
        categoryClass = 'warning';
        icon = '⚠️';
        text = 'SUSPICIOUS';
    } else {
        category = 'safe';
        categoryClass = 'safe';
        icon = '✅';
        text = 'LIKELY SAFE';
    }

    // Animate score number
    animateNumber(scoreValue, 0, score, 800);

    scoreCircle.className = `score-circle ${categoryClass}`;
    verdictIcon.textContent = icon;
    verdictText.className = `verdict-text ${categoryClass}`;
    verdictText.textContent = text;

    // Animate meter
    const meterFill = document.getElementById('meterFill');
    const meterPercent = document.getElementById('meterPercent');

    setTimeout(() => {
        meterFill.style.width = score + '%';
        if (score >= 60) {
            meterFill.style.background = 'linear-gradient(90deg, #ff1744, #ff5252)';
            meterPercent.style.color = '#ff5c7d';
        } else if (score >= 35) {
            meterFill.style.background = 'linear-gradient(90deg, #ff9100, #ffab00)';
            meterPercent.style.color = '#ffc940';
        } else {
            meterFill.style.background = 'linear-gradient(90deg, #00c853, #00e676)';
            meterPercent.style.color = '#69f0ae';
        }
        meterPercent.textContent = score + '%';
    }, 200);

     
    const findingsList = document.getElementById('findingsList');
    findingsList.innerHTML = '';

    if (findings.length === 0) {
        findingsList.innerHTML = `
            <div class="finding-item low">
                <span class="finding-icon">✅</span>
                <div class="finding-text">
                    <strong>No major spam indicators found</strong><br>
                    <span>This email appears to be clean</span>
                </div>
            </div>
        `;
    } else {
        findings.forEach((finding, index) => {
            setTimeout(() => {
                const div = document.createElement('div');
                div.className = `finding-item ${finding.level}`;
                div.innerHTML = `
                    <span class="finding-icon">${finding.icon}</span>
                    <div class="finding-text">
                        <strong>${finding.title}</strong><br>
                        <span>${finding.detail}</span>
                    </div>
                `;
                findingsList.appendChild(div);
            }, index * 100);
        });
    }

     
    const keywordsSection = document.getElementById('keywordsSection');
    const keywordsList = document.getElementById('keywordsList');
    keywordsList.innerHTML = '';

    if (keywords.length > 0) {
        keywordsSection.style.display = 'block';
         
        const uniqueKeywords = [...new Map(keywords.map(k => [k.word.toLowerCase(), k])).values()];
        uniqueKeywords.forEach((kw, index) => {
            setTimeout(() => {
                const tag = document.createElement('span');
                tag.className = `keyword-tag ${kw.level}`;
                tag.textContent = kw.word;
                keywordsList.appendChild(tag);
            }, index * 50);
        });
    } else {
        keywordsSection.style.display = 'none';
    }

  
    generateRecommendations(score, findings, recommendations);

     
    setTimeout(() => {
        resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 300);
}

function generateRecommendations(score, findings) {
    const list = document.getElementById('recommendationsList');
    list.innerHTML = '';
    let recs = [];

    if (score >= 60) {
        recs.push("🚫 Do NOT click any links or download attachments in this email.");
        recs.push("🗑️ Mark this email as spam in your email client.");
        recs.push("🔒 Do NOT reply to this email or provide any personal information.");
        recs.push("📢 Report this email to your email provider as phishing/spam.");
    } else if (score >= 35) {
        recs.push("⚠️ Proceed with caution — verify the sender before taking any action.");
        recs.push("🔍 Hover over links (don't click) to check the actual URL destination.");
        recs.push("📞 If the email claims to be from a company, contact them directly.");
        recs.push("🛡️ Make sure your antivirus and anti-phishing tools are up to date.");
    } else {
        recs.push("✅ This email appears safe, but always verify unexpected senders.");
        recs.push("🔍 Check that links point to legitimate websites before clicking.");
        recs.push("📧 Consider adding this sender to your contacts for future emails.");
    }

    recs.forEach(rec => {
        const li = document.createElement('li');
        li.textContent = rec;
        list.appendChild(li);
    });
}

 
function animateNumber(element, start, end, duration) {
    const range = end - start;
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);

        // Ease out
        const easeOut = 1 - Math.pow(1 - progress, 3);
        const current = Math.round(start + range * easeOut);

        element.textContent = current;

        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }

    requestAnimationFrame(update);
}

function showNotification(message, type) {
    // Remove existing notification
    const existing = document.querySelector('.notification');
    if (existing) existing.remove();

    const notification = document.createElement('div');
    notification.className = 'notification';

    let bgColor;
    switch(type) {
        case 'danger': bgColor = 'linear-gradient(135deg, #ff1744, #d50000)'; break;
        case 'warning': bgColor = 'linear-gradient(135deg, #ff9100, #ff6d00)'; break;
        case 'success': bgColor = 'linear-gradient(135deg, #00c853, #00e676)'; break;
        default: bgColor = 'linear-gradient(135deg, #7b2ff7, #00d2ff)';
    }

    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 16px 24px;
        background: ${bgColor};
        color: white;
        border-radius: 12px;
        font-weight: 600;
        font-size: 0.95rem;
        z-index: 10000;
        box-shadow: 0 8px 30px rgba(0,0,0,0.3);
        animation: slideInRight 0.4s ease;
        max-width: 400px;
    `;
    notification.textContent = message;
    document.body.appendChild(notification);

    // Add animation keyframes
    if (!document.getElementById('notif-style')) {
        const style = document.createElement('style');
        style.id = 'notif-style';
        style.textContent = `
            @keyframes slideInRight {
                from { opacity: 0; transform: translateX(100px); }
                to { opacity: 1; transform: translateX(0); }
            }
        `;
        document.head.appendChild(style);
    }

    setTimeout(() => {
        notification.style.transition = 'all 0.4s ease';
        notification.style.opacity = '0';
        notification.style.transform = 'translateX(100px)';
        setTimeout(() => notification.remove(), 400);
    }, 3500);
}
 
function addToHistory(sender, subject, score) {
    const item = {
        sender: sender || 'Unknown',
        subject: subject || '(No subject)',
        score: score,
        time: new Date().toLocaleTimeString()
    };

    history.unshift(item);
    if (history.length > 10) history.pop();

    renderHistory();
}

function renderHistory() {
    const historySection = document.getElementById('historySection');
    const historyList = document.getElementById('historyList');

    if (history.length === 0) {
        historySection.style.display = 'none';
        return;
    }

    historySection.style.display = 'block';
    historyList.innerHTML = '';

    history.forEach(item => {
        const div = document.createElement('div');
        div.className = 'history-item';

        let badgeClass, badgeText;
        if (item.score >= 60) {
            badgeClass = 'spam';
            badgeText = 'SPAM';
        } else if (item.score >= 35) {
            badgeClass = 'suspicious';
            badgeText = 'SUSPICIOUS';
        } else {
            badgeClass = 'clean';
            badgeText = 'CLEAN';
        }

        div.innerHTML = `
            <span class="history-subject">${item.subject}</span>
            <span style="color: #888; margin-right: 15px; font-size: 0.85rem;">${item.score}%</span>
            <span class="history-badge ${badgeClass}">${badgeText}</span>
        `;
        historyList.appendChild(div);
    });
}

function clearHistory() {
    history = [];
    renderHistory();
    showNotification("🗑️ History cleared!", "success");
}
 
function updateStats() {
    document.getElementById('totalChecked').textContent = stats.totalChecked;
    document.getElementById('totalSpam').textContent = stats.totalSpam;
    document.getElementById('totalClean').textContent = stats.totalClean;
}

function clearAll() {
    document.getElementById('senderEmail').value = '';
    document.getElementById('subjectLine').value = '';
    document.getElementById('emailBody').value = '';
    document.getElementById('resultSection').style.display = 'none';
    showNotification("🗑️ All fields cleared!", "success");
}

function loadSample() {
    document.getElementById('senderEmail').value = 'prince.abdul@nigerian-royal-funds.ng';
    document.getElementById('subjectLine').value = 'CONGRATULATIONS!!! You Have Won $5,500,000 USD!!!';
    document.getElementById('emailBody').value = `Dear Friend`;
    showNotification("📋 Sample spam email loaded! Click Analyze to check it.", "success");
}

//! Matches names against shell patterns with Python's `fnmatch` rules.

#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    Single(char),
    Range(char, char),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Star,
    Any,
    Never,
    Literal(char),
    Class { negated: bool, items: Vec<Item> },
}

impl Token {
    fn accepts(&self, c: char) -> bool {
        match self {
            Token::Any => true,
            Token::Literal(wanted) => c == *wanted,
            Token::Class { negated, items } => {
                let inside = items.iter().any(|item| match item {
                    Item::Single(one) => c == *one,
                    Item::Range(low, high) => *low <= c && c <= *high,
                });
                inside != *negated
            }
            Token::Star | Token::Never => false,
        }
    }
}

/// A compiled shell pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    tokens: Vec<Token>,
}

fn class_items(set: &[char]) -> Vec<Item> {
    let mut items = Vec::new();
    let mut index = 0;
    let read = |index: &mut usize| -> Option<char> {
        let c = *set.get(*index)?;
        *index += 1;
        if c == '\\' {
            let escaped = *set.get(*index)?;
            *index += 1;
            return Some(escaped);
        }
        Some(c)
    };
    while index < set.len() {
        let Some(first) = read(&mut index) else { break };
        if set.get(index) == Some(&'-') && index + 1 < set.len() {
            index += 1;
            if let Some(last) = read(&mut index) {
                items.push(Item::Range(first, last));
                continue;
            }
        }
        items.push(Item::Single(first));
    }
    items
}

fn escape_into(text: &[char], out: &mut Vec<char>, hyphens: bool) {
    for &c in text {
        if c == '\\' || (hyphens && c == '-') {
            out.push('\\');
        }
        out.push(c);
    }
}

fn class_token(pattern: &[char], start: usize, end: usize) -> Token {
    let stuff = &pattern[start..end];
    let mut set: Vec<char> = Vec::new();
    if !stuff.contains(&'-') {
        escape_into(stuff, &mut set, false);
    } else {
        let mut chunks: Vec<Vec<char>> = Vec::new();
        let mut from = start;
        let mut k = if pattern[start] == '!' { start + 2 } else { start + 1 };
        while let Some(found) = (k..end).find(|&p| pattern[p] == '-') {
            chunks.push(pattern[from..found].to_vec());
            from = found + 1;
            k = found + 3;
        }
        let last = pattern[from..end].to_vec();
        if last.is_empty() {
            if let Some(previous) = chunks.last_mut() {
                previous.push('-');
            }
        } else {
            chunks.push(last);
        }
        let mut k = chunks.len().saturating_sub(1);
        while k > 0 {
            let (before, after) = (chunks[k - 1].last().copied(), chunks[k].first().copied());
            if let (Some(before), Some(after)) = (before, after) {
                if before > after {
                    let mut joined: Vec<char> = chunks[k - 1][..chunks[k - 1].len() - 1].to_vec();
                    joined.extend_from_slice(&chunks[k][1..]);
                    chunks[k - 1] = joined;
                    chunks.remove(k);
                }
            }
            k -= 1;
        }
        for (position, chunk) in chunks.iter().enumerate() {
            if position > 0 {
                set.push('-');
            }
            escape_into(chunk, &mut set, true);
        }
    }
    if set.is_empty() {
        return Token::Never;
    }
    if set == ['!'] {
        return Token::Any;
    }
    let negated = set[0] == '!';
    let body = if negated { &set[1..] } else { &set[..] };
    Token::Class { negated, items: class_items(body) }
}

impl Pattern {
    /// Compile a shell pattern. Takes the pattern.
    pub fn new(pattern: &str) -> Pattern {
        let chars: Vec<char> = pattern.chars().collect();
        let mut tokens = Vec::new();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            i += 1;
            match c {
                '*' => {
                    tokens.push(Token::Star);
                    while i < chars.len() && chars[i] == '*' {
                        i += 1;
                    }
                }
                '?' => tokens.push(Token::Any),
                '[' => {
                    let mut j = i;
                    if j < chars.len() && chars[j] == '!' {
                        j += 1;
                    }
                    if j < chars.len() && chars[j] == ']' {
                        j += 1;
                    }
                    while j < chars.len() && chars[j] != ']' {
                        j += 1;
                    }
                    if j >= chars.len() {
                        tokens.push(Token::Literal('['));
                    } else {
                        tokens.push(class_token(&chars, i, j));
                        i = j + 1;
                    }
                }
                other => tokens.push(Token::Literal(other)),
            }
        }
        Pattern { tokens }
    }

    /// Tell whether a whole name matches. Takes the name.
    pub fn matches(&self, name: &str) -> bool {
        let name: Vec<char> = name.chars().collect();
        let (mut t, mut n) = (0, 0);
        let mut retry: Option<(usize, usize)> = None;
        loop {
            if t < self.tokens.len() {
                if self.tokens[t] == Token::Star {
                    retry = Some((t + 1, n));
                    t += 1;
                    continue;
                }
                if n < name.len() && self.tokens[t].accepts(name[n]) {
                    t += 1;
                    n += 1;
                    continue;
                }
            } else if n == name.len() {
                return true;
            }
            match retry {
                Some((after_star, start)) if start < name.len() => {
                    retry = Some((after_star, start + 1));
                    t = after_star;
                    n = start + 1;
                }
                _ => return false,
            }
        }
    }
}

/// Tell whether a name matches a shell pattern, case included. Takes the name and the pattern.
pub fn matches(name: &str, pattern: &str) -> bool {
    Pattern::new(pattern).matches(name)
}

/// Tell whether a name matches a shell pattern as Windows compares paths. Takes the name and the
/// pattern.
pub fn matches_windows(name: &str, pattern: &str) -> bool {
    let fold = |text: &str| text.replace('/', "\\").to_lowercase();
    matches(&fold(name), &fold(pattern))
}

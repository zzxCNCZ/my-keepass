use serde::{Deserialize, Serialize};

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMBERS: &str = "0123456789";
const SPECIAL: &str = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
const LOOK_ALIKE: &str = "l1I0O|";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordOptions {
    pub length: usize,
    pub lower: bool,
    pub upper: bool,
    pub numbers: bool,
    pub special: bool,
    #[serde(default)]
    pub custom: String,
    #[serde(default)]
    pub exclude_look_alike: bool,
    #[serde(default = "default_true")]
    pub every_group: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedPassword {
    pub password: String,
    pub entropy_bits: f64,
    pub strength: u8,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordStrength {
    pub entropy_bits: f64,
    pub strength: u8,
}

fn random_u32() -> Result<u32, String> {
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).map_err(|error| format!("随机数生成失败：{error}"))?;
    Ok(u32::from_le_bytes(bytes))
}

fn random_index(bound: usize) -> Result<usize, String> {
    if bound <= 1 {
        return Ok(0);
    }
    let bound_u32 = u32::try_from(bound).map_err(|_| "字符集过大。".to_string())?;
    let limit = u32::MAX - (u32::MAX % bound_u32);
    loop {
        let value = random_u32()?;
        if value < limit {
            return Ok((value % bound_u32) as usize);
        }
    }
}

fn filter_chars(source: &str, exclude_look_alike: bool) -> Vec<char> {
    let mut chars = Vec::new();
    for ch in source.chars() {
        if ch.is_control() {
            continue;
        }
        if exclude_look_alike && LOOK_ALIKE.contains(ch) {
            continue;
        }
        if !chars.contains(&ch) {
            chars.push(ch);
        }
    }
    chars
}

pub fn generate(options: &PasswordOptions) -> Result<GeneratedPassword, String> {
    if options.length < 4 || options.length > 256 {
        return Err("密码长度须在 4 到 256 之间。".into());
    }
    let mut groups: Vec<Vec<char>> = Vec::new();
    if options.lower {
        let chars = filter_chars(LOWER, options.exclude_look_alike);
        if !chars.is_empty() {
            groups.push(chars);
        }
    }
    if options.upper {
        let chars = filter_chars(UPPER, options.exclude_look_alike);
        if !chars.is_empty() {
            groups.push(chars);
        }
    }
    if options.numbers {
        let chars = filter_chars(NUMBERS, options.exclude_look_alike);
        if !chars.is_empty() {
            groups.push(chars);
        }
    }
    if options.special {
        let chars = filter_chars(SPECIAL, options.exclude_look_alike);
        if !chars.is_empty() {
            groups.push(chars);
        }
    }
    if !options.custom.is_empty() {
        let chars = filter_chars(&options.custom, options.exclude_look_alike);
        if !chars.is_empty() {
            groups.push(chars);
        }
    }
    if groups.is_empty() {
        return Err("请至少选择一种字符集。".into());
    }
    if options.every_group && options.length < groups.len() {
        return Err("密码长度不能小于已选字符分组数量。".into());
    }

    let mut pool: Vec<char> = Vec::new();
    for group in &groups {
        for &ch in group {
            if !pool.contains(&ch) {
                pool.push(ch);
            }
        }
    }

    let mut result = Vec::with_capacity(options.length);
    if options.every_group {
        for group in &groups {
            let idx = random_index(group.len())?;
            result.push(group[idx]);
        }
    }
    while result.len() < options.length {
        let idx = random_index(pool.len())?;
        result.push(pool[idx]);
    }

    // Unbiased Fisher-Yates shuffle
    for i in (1..result.len()).rev() {
        let j = random_index(i + 1)?;
        result.swap(i, j);
    }

    let password: String = result.into_iter().collect();
    let entropy_bits = (options.length as f64) * (pool.len() as f64).log2();
    let strength = entropy_to_strength(entropy_bits);
    Ok(GeneratedPassword {
        password,
        entropy_bits: (entropy_bits * 10.0).round() / 10.0,
        strength,
    })
}

pub fn estimate_strength(password: &str) -> PasswordStrength {
    if password.is_empty() {
        return PasswordStrength {
            entropy_bits: 0.0,
            strength: 0,
        };
    }
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_special = false;
    let mut has_unicode = false;
    for ch in password.chars() {
        if ch.is_ascii_lowercase() {
            has_lower = true;
        } else if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if ch.is_ascii_digit() {
            has_digit = true;
        } else if ch.is_ascii_punctuation() || ch == ' ' {
            has_special = true;
        } else {
            has_unicode = true;
        }
    }
    let mut pool = 0u32;
    if has_lower {
        pool += 26;
    }
    if has_upper {
        pool += 26;
    }
    if has_digit {
        pool += 10;
    }
    if has_special {
        pool += 33;
    }
    if has_unicode {
        pool += 64;
    }
    let length = password.chars().count() as f64;
    let bits = if pool > 1 {
        length * (pool as f64).log2()
    } else {
        0.0
    };
    PasswordStrength {
        entropy_bits: (bits * 10.0).round() / 10.0,
        strength: entropy_to_strength(bits),
    }
}

fn entropy_to_strength(bits: f64) -> u8 {
    if bits < 28.0 {
        0
    } else if bits < 45.0 {
        1
    } else if bits < 65.0 {
        2
    } else if bits < 95.0 {
        3
    } else {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_password_honoring_classes_and_look_alike_exclusion() {
        let opts = PasswordOptions {
            length: 24,
            lower: true,
            upper: true,
            numbers: true,
            special: true,
            custom: String::new(),
            exclude_look_alike: true,
            every_group: true,
        };
        let generated = generate(&opts).unwrap();
        assert_eq!(generated.password.chars().count(), 24);
        assert!(generated.password.chars().all(|c| !LOOK_ALIKE.contains(c)));
        assert!(generated.password.chars().any(|c| c.is_ascii_lowercase()));
        assert!(generated.password.chars().any(|c| c.is_ascii_uppercase()));
        assert!(generated.password.chars().any(|c| c.is_ascii_digit()));
        assert!(generated.password.chars().any(|c| SPECIAL.contains(c)));
        assert!(generated.entropy_bits > 100.0);
        assert_eq!(generated.strength, 4);
    }

    #[test]
    fn rejects_invalid_password_options() {
        let empty = PasswordOptions {
            length: 16,
            lower: false,
            upper: false,
            numbers: false,
            special: false,
            custom: String::new(),
            exclude_look_alike: false,
            every_group: true,
        };
        assert!(generate(&empty).is_err());

        let short = PasswordOptions {
            length: 2,
            lower: true,
            upper: true,
            numbers: true,
            special: false,
            custom: String::new(),
            exclude_look_alike: false,
            every_group: true,
        };
        assert!(generate(&short).is_err());
    }
}

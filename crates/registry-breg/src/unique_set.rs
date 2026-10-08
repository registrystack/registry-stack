// SPDX-License-Identifier: Apache-2.0

//! A set an author writes as a list.

use std::collections::BTreeSet;
use std::hash::Hash;
use std::ops::{Deref, DerefMut};

use registry_platform_yaml::UniqueList;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A set an author writes as a list. It is read through the shared reader's
/// `UniqueList`, so a repeated item is refused with `config.duplicate-item`
/// instead of being collapsed (CFG-ID-6), and its schema declares
/// `uniqueItems: true`. The compiler reads it as the ordered set it holds,
/// and it serializes in that order.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct UniqueSet<T: Ord>(BTreeSet<T>);

impl<T: Ord> UniqueSet<T> {
    pub fn new() -> Self {
        UniqueSet(BTreeSet::new())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_set(&self) -> &BTreeSet<T> {
        &self.0
    }

    pub fn into_set(self) -> BTreeSet<T> {
        self.0
    }
}

impl<T: Ord> Default for UniqueSet<T> {
    fn default() -> Self {
        UniqueSet(BTreeSet::new())
    }
}

impl<T: Ord> Deref for UniqueSet<T> {
    type Target = BTreeSet<T>;

    fn deref(&self) -> &BTreeSet<T> {
        &self.0
    }
}

impl<T: Ord> DerefMut for UniqueSet<T> {
    fn deref_mut(&mut self) -> &mut BTreeSet<T> {
        &mut self.0
    }
}

impl<T: Ord> From<BTreeSet<T>> for UniqueSet<T> {
    fn from(set: BTreeSet<T>) -> Self {
        UniqueSet(set)
    }
}

impl<T: Ord, const N: usize> From<[T; N]> for UniqueSet<T> {
    fn from(items: [T; N]) -> Self {
        UniqueSet(BTreeSet::from(items))
    }
}

impl<T: Ord> From<UniqueSet<T>> for BTreeSet<T> {
    fn from(set: UniqueSet<T>) -> Self {
        set.0
    }
}

impl<T: Ord> FromIterator<T> for UniqueSet<T> {
    fn from_iter<I: IntoIterator<Item = T>>(items: I) -> Self {
        UniqueSet(items.into_iter().collect())
    }
}

impl<'s, T: Ord> IntoIterator for &'s UniqueSet<T> {
    type Item = &'s T;
    type IntoIter = std::collections::btree_set::Iter<'s, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T: Ord> IntoIterator for UniqueSet<T> {
    type Item = T;
    type IntoIter = std::collections::btree_set::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T: Ord + Serialize> Serialize for UniqueSet<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Ord + Hash + Deserialize<'de>> Deserialize<'de> for UniqueSet<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        UniqueList::<T>::deserialize(deserializer).map(|items| items.into_iter().collect())
    }
}

#[cfg(feature = "schema")]
impl<T: Ord + schemars::JsonSchema> schemars::JsonSchema for UniqueSet<T> {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        UniqueList::<T>::schema_name()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        UniqueList::<T>::json_schema(generator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_repeated_item_is_refused_rather_than_collapsed() {
        let refused = serde_json::from_str::<UniqueSet<String>>(r#"["a","b","a"]"#)
            .expect_err("a repeated item is refused");
        assert!(
            refused.to_string().contains("item 2 repeats item 0"),
            "{refused}"
        );
        let read = serde_json::from_str::<UniqueSet<String>>(r#"["b","a"]"#)
            .expect("distinct items are read");
        assert_eq!(read, UniqueSet::from(["a".to_owned(), "b".to_owned()]));
        assert_eq!(
            serde_json::to_string(&read).expect("the set serializes"),
            r#"["a","b"]"#
        );
    }
}

use std::{
    cmp::Ordering,
    ops::{Index, IndexMut},
    slice::Iter,
};

#[derive(Clone)]
pub struct MemorySegment {
    pub memory: Vec<u8>,
}

pub struct MemoryTable {
    inner: Vec<(MemorySegment, i64)>,
    reservation: Option<(i64, usize)>,
}

impl MemoryTable {
    pub fn new() -> Self {
        MemoryTable {
            inner: Vec::new(),
            reservation: None,
        }
    }

    pub fn push(&mut self, segment: (MemorySegment, i64)) {
        self.inner.push(segment);
        self.inner
            .sort_by(|s1, s2: &(MemorySegment, i64)| s1.1.cmp(&s2.1));
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn last_mut(&mut self) -> Option<&mut (MemorySegment, i64)> {
        self.inner.last_mut()
    }

    pub fn reserve(&mut self, addr: i64, size: usize) {
        self.reservation = Some((addr, size))
    }

    pub fn invalidate_reservation(&mut self) {
        self.reservation = None
    }

    pub fn check_reservation(&self, addr: i64, size: usize) -> bool {
        if let Some(reservation) = self.reservation {
            return addr >= reservation.0
                && (addr + size as i64) <= (reservation.0 + reservation.1 as i64);
        } else {
            return false;
        }
    }

    pub fn map_address(&self, addr: i64) -> Option<(&Vec<u8>, usize)> {
        if let Ok(idx) = self.inner.binary_search_by(|s| {
            if addr < s.1 {
                Ordering::Greater
            } else if addr >= s.1 + s.0.memory.len() as i64 {
                Ordering::Less
            } else {
                Ordering::Equal
            }
        }) {
            let segment = &self.inner[idx];
            Some((&segment.0.memory, (addr - segment.1).try_into().unwrap()))
        } else {
            None
        }
    }

    pub fn map_address_mut(&mut self, addr: i64) -> Option<(&mut Vec<u8>, usize)> {
        if let Some(reservation) = self.reservation {
            if reservation.0 <= addr && addr < reservation.0 + reservation.1 as i64 {
                self.reservation = None // invalidate reserved_addr
            }
        }

        if let Ok(idx) = self.inner.binary_search_by(|s| {
            if addr < s.1 {
                Ordering::Greater
            } else if addr >= s.0.memory.len() as i64 + s.1 {
                Ordering::Less
            } else {
                Ordering::Equal
            }
        }) {
            let segment = &mut self.inner[idx];
            Some((
                &mut segment.0.memory,
                (addr - segment.1).try_into().unwrap(),
            ))
        } else {
            None
        }
    }
}

impl<'a> IntoIterator for &'a MemoryTable {
    type Item = &'a (MemorySegment, i64);

    type IntoIter = Iter<'a, (MemorySegment, i64)>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

impl Index<usize> for MemoryTable {
    type Output = (MemorySegment, i64);

    fn index(&self, index: usize) -> &Self::Output {
        self.inner.index(index)
    }
}

impl IndexMut<usize> for MemoryTable {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        self.inner.index_mut(index)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PieceSource {
    Original,
    AddBuffer,
}

#[derive(Debug, Clone)]
pub struct Piece {
    pub source: PieceSource,
    pub start: usize,
    pub length: usize,
}

pub struct PieceTable {
    pieces: Vec<Piece>,
    original: Vec<u8>,
    add_buffer: Vec<u8>,
    total_length: usize,
}

impl PieceTable {
    #[must_use]
    pub fn new(data: &[u8]) -> Self {
        let length = data.len();
        let pieces = if length > 0 {
            vec![Piece {
                source: PieceSource::Original,
                start: 0,
                length,
            }]
        } else {
            Vec::new()
        };

        Self {
            pieces,
            original: data.to_vec(),
            add_buffer: Vec::new(),
            total_length: length,
        }
    }

    #[must_use]
    pub fn length(&self) -> usize {
        self.total_length
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total_length == 0
    }

    #[must_use]
    pub fn find_piece(&self, offset: usize) -> Option<(usize, usize)> {
        if offset >= self.total_length || self.pieces.is_empty() {
            return None;
        }

        let mut accumulated: usize = 0;
        for (idx, piece) in self.pieces.iter().enumerate() {
            if offset < accumulated + piece.length {
                return Some((idx, offset - accumulated));
            }
            accumulated += piece.length;
        }
        None
    }

    fn get_buffer(&self, source: PieceSource) -> &[u8] {
        match source {
            PieceSource::Original => &self.original,
            PieceSource::AddBuffer => &self.add_buffer,
        }
    }

    #[must_use]
    pub fn read_byte(&self, offset: usize) -> Option<u8> {
        let (piece_idx, inner_offset) = self.find_piece(offset)?;
        let piece = &self.pieces[piece_idx];
        let buf = self.get_buffer(piece.source);
        Some(buf[piece.start + inner_offset])
    }

    #[must_use]
    pub fn read(&self, offset: usize, length: usize) -> Vec<u8> {
        if length == 0 || offset >= self.total_length {
            return Vec::new();
        }

        let actual_length = length.min(self.total_length - offset);
        let mut result = Vec::with_capacity(actual_length);
        let mut remaining = actual_length;
        let mut current_offset = offset;

        while remaining > 0 {
            let Some((piece_idx, inner_offset)) = self.find_piece(current_offset) else {
                break;
            };

            let piece = &self.pieces[piece_idx];
            let buf = self.get_buffer(piece.source);
            let available = piece.length - inner_offset;
            let to_copy = remaining.min(available);

            let buf_start = piece.start + inner_offset;
            result.extend_from_slice(&buf[buf_start..buf_start + to_copy]);

            remaining -= to_copy;
            current_offset += to_copy;
        }

        result
    }

    /// Inserts data at the given offset.
    ///
    /// # Panics
    ///
    /// Panics if `find_piece` returns `None` for a valid in-range offset, which
    /// indicates internal state corruption.
    pub fn insert(&mut self, offset: usize, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        let add_start = self.add_buffer.len();
        self.add_buffer.extend_from_slice(data);

        let new_piece = Piece {
            source: PieceSource::AddBuffer,
            start: add_start,
            length: data.len(),
        };

        if self.pieces.is_empty() || offset >= self.total_length {
            self.pieces.push(new_piece);
        } else if offset == 0 {
            self.pieces.insert(0, new_piece);
        } else {
            let (piece_idx, inner_offset) = self
                .find_piece(offset)
                .expect("invariant: offset within bounds after guard");

            if inner_offset == 0 {
                self.pieces.insert(piece_idx, new_piece);
            } else {
                let old_piece = self.pieces[piece_idx].clone();

                let left = Piece {
                    source: old_piece.source,
                    start: old_piece.start,
                    length: inner_offset,
                };
                let right = Piece {
                    source: old_piece.source,
                    start: old_piece.start + inner_offset,
                    length: old_piece.length - inner_offset,
                };

                self.pieces[piece_idx] = left;
                self.pieces.insert(piece_idx + 1, new_piece);
                self.pieces.insert(piece_idx + 2, right);
            }
        }

        self.total_length += data.len();
    }

    pub fn overwrite(&mut self, offset: usize, data: &[u8]) {
        if data.is_empty() || offset >= self.total_length {
            return;
        }

        let actual_len = data.len().min(self.total_length - offset);
        self.delete(offset, actual_len);
        self.insert(offset, &data[..actual_len]);
    }

    /// Deletes `length` bytes starting at the given offset.
    ///
    /// # Panics
    ///
    /// Panics if the piece list is non-empty but `last()` returns `None`, which
    /// indicates internal state corruption.
    pub fn delete(&mut self, offset: usize, length: usize) {
        if length == 0 || offset >= self.total_length {
            return;
        }

        let actual_length = length.min(self.total_length - offset);
        let end = offset + actual_length;

        let Some((start_piece_idx, start_inner)) = self.find_piece(offset) else {
            return;
        };

        let (end_piece_idx, end_inner) = if end >= self.total_length {
            (
                self.pieces.len() - 1,
                self.pieces
                    .last()
                    .expect("invariant: pieces non-empty after length guard")
                    .length,
            )
        } else {
            match self.find_piece(end) {
                Some(v) => v,
                None => (
                    self.pieces.len() - 1,
                    self.pieces
                        .last()
                        .expect("invariant: pieces non-empty after length guard")
                        .length,
                ),
            }
        };

        let mut new_pieces: Vec<Piece> = Vec::new();

        new_pieces.extend_from_slice(&self.pieces[..start_piece_idx]);

        if start_inner > 0 {
            let piece = &self.pieces[start_piece_idx];
            new_pieces.push(Piece {
                source: piece.source,
                start: piece.start,
                length: start_inner,
            });
        }

        let piece = &self.pieces[end_piece_idx];
        if end_inner < piece.length {
            new_pieces.push(Piece {
                source: piece.source,
                start: piece.start + end_inner,
                length: piece.length - end_inner,
            });
        }

        if end_piece_idx + 1 < self.pieces.len() {
            new_pieces.extend_from_slice(&self.pieces[end_piece_idx + 1..]);
        }

        self.pieces = new_pieces;
        self.total_length -= actual_length;
    }

    #[must_use]
    pub fn materialize(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.total_length);
        for piece in &self.pieces {
            let buf = self.get_buffer(piece.source);
            result.extend_from_slice(&buf[piece.start..piece.start + piece.length]);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_empty() {
        let pt = PieceTable::new(&[]);
        assert_eq!(pt.length(), 0);
        assert!(pt.is_empty());
        assert_eq!(pt.read(0, 10), Vec::<u8>::new());
    }

    #[test]
    fn test_new_with_data() {
        let data = b"Hello, World!";
        let pt = PieceTable::new(data);
        assert_eq!(pt.length(), 13);
        assert_eq!(pt.read(0, 13), data.to_vec());
    }

    #[test]
    fn test_read_byte() {
        let pt = PieceTable::new(b"ABCDE");
        assert_eq!(pt.read_byte(0), Some(b'A'));
        assert_eq!(pt.read_byte(4), Some(b'E'));
        assert_eq!(pt.read_byte(5), None);
    }

    #[test]
    fn test_read_partial() {
        let pt = PieceTable::new(b"Hello, World!");
        assert_eq!(pt.read(7, 5), b"World".to_vec());
    }

    #[test]
    fn test_read_beyond_end() {
        let pt = PieceTable::new(b"ABC");
        assert_eq!(pt.read(1, 100), b"BC".to_vec());
    }

    #[test]
    fn test_insert_at_start() {
        let mut pt = PieceTable::new(b"World");
        pt.insert(0, b"Hello ");
        assert_eq!(pt.length(), 11);
        assert_eq!(pt.read(0, 11), b"Hello World".to_vec());
    }

    #[test]
    fn test_insert_at_end() {
        let mut pt = PieceTable::new(b"Hello");
        pt.insert(5, b" World");
        assert_eq!(pt.length(), 11);
        assert_eq!(pt.read(0, 11), b"Hello World".to_vec());
    }

    #[test]
    fn test_insert_in_middle() {
        let mut pt = PieceTable::new(b"abcd");
        pt.insert(2, b"XX");
        assert_eq!(pt.length(), 6);
        assert_eq!(pt.read(0, 6), b"abXXcd".to_vec());
    }

    #[test]
    fn test_insert_into_empty() {
        let mut pt = PieceTable::new(&[]);
        pt.insert(0, b"ABC");
        assert_eq!(pt.length(), 3);
        assert_eq!(pt.read(0, 3), b"ABC".to_vec());
    }

    #[test]
    fn test_overwrite() {
        let mut pt = PieceTable::new(b"Hello World");
        pt.overwrite(6, b"Rust!");
        assert_eq!(pt.length(), 11);
        assert_eq!(pt.read(0, 11), b"Hello Rust!".to_vec());
    }

    #[test]
    fn test_overwrite_at_boundary() {
        let mut pt = PieceTable::new(b"AABB");
        pt.overwrite(0, b"XX");
        assert_eq!(pt.read(0, 4), b"XXBB".to_vec());
    }

    #[test]
    fn test_delete_from_start() {
        let mut pt = PieceTable::new(b"Hello World");
        pt.delete(0, 6);
        assert_eq!(pt.length(), 5);
        assert_eq!(pt.read(0, 5), b"World".to_vec());
    }

    #[test]
    fn test_delete_from_end() {
        let mut pt = PieceTable::new(b"Hello World");
        pt.delete(5, 6);
        assert_eq!(pt.length(), 5);
        assert_eq!(pt.read(0, 5), b"Hello".to_vec());
    }

    #[test]
    fn test_delete_from_middle() {
        let mut pt = PieceTable::new(b"Hello World");
        pt.delete(5, 1);
        assert_eq!(pt.length(), 10);
        assert_eq!(pt.read(0, 10), b"HelloWorld".to_vec());
    }

    #[test]
    fn test_delete_all() {
        let mut pt = PieceTable::new(b"ABC");
        pt.delete(0, 3);
        assert_eq!(pt.length(), 0);
        assert!(pt.is_empty());
    }

    #[test]
    fn test_multiple_operations() {
        let mut pt = PieceTable::new(b"ABCDEF");
        pt.insert(3, b"XY");
        assert_eq!(pt.read(0, 8), b"ABCXYDEF".to_vec());
        pt.delete(1, 2);
        assert_eq!(pt.read(0, 6), b"AXYDEF".to_vec());
        pt.overwrite(0, b"Z");
        assert_eq!(pt.read(0, 6), b"ZXYDEF".to_vec());
    }

    #[test]
    fn test_cross_piece_read() {
        let mut pt = PieceTable::new(b"AABBCC");
        pt.insert(2, b"XX");
        let data = pt.read(1, 4);
        assert_eq!(data, b"AXXB".to_vec());
    }

    #[test]
    fn test_materialize() {
        let mut pt = PieceTable::new(b"Hello");
        pt.insert(5, b" World");
        pt.overwrite(0, b"h");
        let mat = pt.materialize();
        assert_eq!(mat, b"hello World".to_vec());
    }

    #[test]
    fn test_large_insert() {
        let mut pt = PieceTable::new(&[0u8; 1000]);
        let insert_data = vec![0xFFu8; 500];
        pt.insert(500, &insert_data);
        assert_eq!(pt.length(), 1500);
        assert_eq!(pt.read_byte(499), Some(0x00));
        assert_eq!(pt.read_byte(500), Some(0xFF));
        assert_eq!(pt.read_byte(999), Some(0xFF));
        assert_eq!(pt.read_byte(1000), Some(0x00));
    }
}

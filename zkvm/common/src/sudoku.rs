#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecompressionError;
impl std::fmt::Display for DecompressionError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("compact sudoku board representation is non-standard")
    }
}
impl std::error::Error for DecompressionError {}

/// A sudoku board encoded as 9 x [`u32`], where each [`u32`] encodes a row of nine base-10 digits.
/// The 32-bit numbers are serialized in big-endian format, and then concatenated to form a
/// 36-byte array.
///
/// To ensure a 1-to-1 (bijective) mapping between compact and standard representations of sudoku
/// boards, any encodings which contain a `u32` larger than `999_999_999` are rejected when
/// decompressing.
///
/// By representing the encrypted solution board in this compact format within the RISC0 guest,
/// we reduce the amount of data we need to run through the chosen cipher by more than a factor of two.
pub type CompactSudokuBoard = [u8; 36];

/// Compresses a sudoku board from a full 81-byte representation down to a compact
/// set of 9 big-endian-serialized `u32`s.
pub fn compress_board(board: &SudokuBoard) -> CompactSudokuBoard {
    let mut compact_bytes = [0u8; 36];
    for i in 0..9 {
        let row_start = i * 9;
        let mut row_u32_rep: u32 = 0;
        for j in 0..9 {
            row_u32_rep = row_u32_rep * 10 + board[row_start + j] as u32;
        }

        compact_bytes[i * 4..][..4].copy_from_slice(&row_u32_rep.to_be_bytes());
    }
    compact_bytes
}

/// Decompress a sudoku board from a compact 36-byte representation back to the full
/// one-cell-per-byte format (81 bytes).
pub fn decompress_board(
    compact_bytes: &CompactSudokuBoard,
) -> Result<SudokuBoard, DecompressionError> {
    let mut board = [0u8; 81];
    for i in 0..9 {
        let u32_bytes = <[u8; 4]>::try_from(&compact_bytes[i * 4..][..4]).unwrap();
        let mut row_u32_rep = u32::from_be_bytes(u32_bytes);

        // Malleable row representations are not allowed
        if row_u32_rep > 999_999_999 {
            return Err(DecompressionError);
        }

        let row_start = i * 9;
        for j in (0..9).rev() {
            board[row_start + j] = (row_u32_rep % 10) as u8;
            row_u32_rep /= 10;
        }
    }
    Ok(board)
}

/// Represents a 9x9 sudoku board. Cell indexes are
/// read left to right, top to bottom.
pub type SudokuBoard = [u8; 81];

fn check_valid_digit(digit: u8, seen: &mut [bool; 9]) -> bool {
    if !(1..=9).contains(&digit) {
        return false;
    }

    let i = (digit - 1) as usize;
    if seen[i] {
        return false;
    }
    seen[i] = true;

    true
}

/// Mask a sudoku solution, turning it from a solution into a puzzle by setting specific
/// cells on the board to zero. Think of this as converting a sudoku solution into a sudoku
/// puzzle.
///
/// The `mask` board must contain only zeros and ones.
///
/// The output follows these rules:
/// - Any cells in the mask board set to `0` are also set to `0`.
/// - Any cells in the mask board set to `1` are set to the value of the same cell
///   on the `solution` board.
///
/// This function panics if `mask` contains any bytes which are neither zero nor one.
pub fn mask_sudoku_solution(solution: &SudokuBoard, mask: &SudokuBoard) -> SudokuBoard {
    let mut puzzle = *solution;
    for i in 0..81 {
        if mask[i] == 0 {
            puzzle[i] = 0;
        } else if mask[i] != 1 {
            panic!("invalid mask");
        }
    }
    puzzle
}

/// Tests if a given sudoku board is valid according to the rules of sudoku.
/// This means:
///
/// - Each of the 9 rows contain the digits `[1, 2, 3, ... 9]`
/// - Each of the 9 columns contain the digits `[1, 2, 3, ... 9]`
/// - Each of the 9 three-by-three subgrids contain the digits `[1, 2, 3, ... 9]`
///
/// If any of these conditions fail, this function returns false.
pub fn is_valid_sudoku_solution(board: &SudokuBoard) -> bool {
    // Rows contain all digits [1...9]
    for row in 0..9 {
        let mut seen = [false; 9];
        let row_times_9 = row * 9;
        for column in 0..9 {
            if !check_valid_digit(board[row_times_9 + column], &mut seen) {
                return false;
            };
        }
    }

    // Columns contain all digits [1...9]
    for column in 0..9 {
        let mut seen = [false; 9];
        for row in 0..9 {
            if !check_valid_digit(board[row * 9 + column], &mut seen) {
                return false;
            };
        }
    }

    // Subgrids contain all digits [1...9]
    for grid in 0..9 {
        let mut seen = [false; 9];
        let grid_row_start = grid / 3 * 3;
        let grid_col_start = (grid % 3) * 3;
        for i in 0..9 {
            let row = grid_row_start + (i / 3);
            let column = grid_col_start + (i % 3);
            if !check_valid_digit(board[row * 9 + column], &mut seen) {
                return false;
            };
        }
    }

    true
}

/// Returns true if the given `solution` matches the `puzzle`, excluding
/// cells set to `0` in the puzzle.
///
/// More precisely, we return true if and only if, for all `i` in `0..81`:
///
/// ```not_rust
/// puzzle[i] == 0 || solution[i] == puzzle[i]
/// ```
pub fn solves_sudoku_puzzle(solution: &SudokuBoard, puzzle: &SudokuBoard) -> bool {
    solution.iter().zip(puzzle).all(|(&s, &p)| p == 0 || s == p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_sudoku_solution() {
        assert!(is_valid_sudoku_solution(&[
            6, 1, 4, /**/ 3, 8, 9, /**/ 2, 5, 7, //
            5, 8, 3, /**/ 6, 7, 2, /**/ 4, 1, 9, //
            9, 7, 2, /**/ 5, 4, 1, /**/ 8, 6, 3, //
            /***********************************/
            1, 3, 9, /**/ 8, 5, 4, /**/ 6, 7, 2, //
            2, 5, 8, /**/ 1, 6, 7, /**/ 9, 3, 4, //
            7, 4, 6, /**/ 2, 9, 3, /**/ 5, 8, 1, //
            /***********************************/
            8, 2, 7, /**/ 9, 1, 5, /**/ 3, 4, 6, //
            4, 9, 5, /**/ 7, 3, 6, /**/ 1, 2, 8, //
            3, 6, 1, /**/ 4, 2, 8, /**/ 7, 9, 5, //
        ]));

        assert!(!is_valid_sudoku_solution(&[
            0, 1, 4, /**/ 3, 8, 9, /**/ 2, 5, 7, //
            5, 8, 3, /**/ 6, 7, 2, /**/ 4, 1, 9, //
            9, 7, 2, /**/ 5, 4, 1, /**/ 8, 6, 3, //
            /***********************************/
            1, 3, 9, /**/ 8, 5, 4, /**/ 6, 7, 2, //
            2, 5, 8, /**/ 1, 6, 7, /**/ 9, 3, 4, //
            7, 4, 6, /**/ 2, 9, 3, /**/ 5, 8, 1, //
            /***********************************/
            8, 2, 7, /**/ 9, 1, 5, /**/ 3, 4, 6, //
            4, 9, 5, /**/ 7, 3, 6, /**/ 1, 2, 8, //
            3, 6, 1, /**/ 4, 2, 8, /**/ 7, 9, 5, //
        ]));

        assert!(!is_valid_sudoku_solution(&[
            6, 1, 6, /**/ 3, 8, 9, /**/ 2, 5, 7, //
            5, 8, 3, /**/ 6, 7, 2, /**/ 4, 1, 9, //
            9, 7, 2, /**/ 5, 4, 1, /**/ 8, 6, 3, //
            /***********************************/
            1, 3, 9, /**/ 8, 5, 4, /**/ 6, 7, 2, //
            2, 5, 8, /**/ 1, 6, 7, /**/ 9, 3, 4, //
            7, 4, 6, /**/ 2, 9, 3, /**/ 5, 8, 1, //
            /***********************************/
            8, 2, 7, /**/ 9, 1, 5, /**/ 3, 4, 6, //
            4, 9, 5, /**/ 7, 3, 6, /**/ 1, 2, 8, //
            3, 6, 1, /**/ 4, 2, 8, /**/ 7, 9, 5, //
        ]));
    }

    #[test]
    fn test_mask_sudoku_solution() {
        let mut mask = [1u8; 81];
        for i in 0..9 {
            mask[i] = 0;
            mask[i * 9] = 0;
        }
        let solution = [
            6, 1, 4, /**/ 3, 8, 9, /**/ 2, 5, 7, //
            5, 8, 3, /**/ 6, 7, 2, /**/ 4, 1, 9, //
            9, 7, 2, /**/ 5, 4, 1, /**/ 8, 6, 3, //
            /***********************************/
            1, 3, 9, /**/ 8, 5, 4, /**/ 6, 7, 2, //
            2, 5, 8, /**/ 1, 6, 7, /**/ 9, 3, 4, //
            7, 4, 6, /**/ 2, 9, 3, /**/ 5, 8, 1, //
            /***********************************/
            8, 2, 7, /**/ 9, 1, 5, /**/ 3, 4, 6, //
            4, 9, 5, /**/ 7, 3, 6, /**/ 1, 2, 8, //
            3, 6, 1, /**/ 4, 2, 8, /**/ 7, 9, 5, //
        ];

        assert_eq!(
            mask_sudoku_solution(&solution, &mask),
            [
                0, 0, 0, /**/ 0, 0, 0, /**/ 0, 0, 0, //
                0, 8, 3, /**/ 6, 7, 2, /**/ 4, 1, 9, //
                0, 7, 2, /**/ 5, 4, 1, /**/ 8, 6, 3, //
                /***********************************/
                0, 3, 9, /**/ 8, 5, 4, /**/ 6, 7, 2, //
                0, 5, 8, /**/ 1, 6, 7, /**/ 9, 3, 4, //
                0, 4, 6, /**/ 2, 9, 3, /**/ 5, 8, 1, //
                /***********************************/
                0, 2, 7, /**/ 9, 1, 5, /**/ 3, 4, 6, //
                0, 9, 5, /**/ 7, 3, 6, /**/ 1, 2, 8, //
                0, 6, 1, /**/ 4, 2, 8, /**/ 7, 9, 5, //
            ]
        )
    }

    #[test]
    fn test_compact_board_representation() {
        let board = [
            6, 1, 4, /**/ 3, 8, 9, /**/ 2, 5, 7, //
            5, 8, 3, /**/ 6, 7, 2, /**/ 4, 1, 9, //
            9, 7, 2, /**/ 5, 4, 1, /**/ 8, 6, 3, //
            /***********************************/
            1, 3, 9, /**/ 8, 5, 4, /**/ 6, 7, 2, //
            2, 5, 8, /**/ 1, 6, 7, /**/ 9, 3, 4, //
            7, 4, 6, /**/ 2, 9, 3, /**/ 5, 8, 1, //
            /***********************************/
            8, 2, 7, /**/ 9, 1, 5, /**/ 3, 4, 6, //
            4, 9, 5, /**/ 7, 3, 6, /**/ 1, 2, 8, //
            3, 6, 1, /**/ 4, 2, 8, /**/ 7, 9, 5, //
        ];

        let compact_board = compress_board(&board);

        let rows: Vec<u32> = compact_board
            .chunks(4)
            .map(|bytes| {
                (bytes[0] as u32) << 24
                    | (bytes[1] as u32) << 16
                    | (bytes[2] as u32) << 8
                    | (bytes[3] as u32) << 0
            })
            .collect();

        assert_eq!(
            rows,
            vec![
                614_389_257,
                583_672_419,
                972_541_863,
                139_854_672,
                258_167_934,
                746_293_581,
                827_915_346,
                495_736_128,
                361_428_795,
            ]
        );

        assert_eq!(decompress_board(&compress_board(&board)), Ok(board));
        assert!(decompress_board(&[0xFF; 36]).is_err());
    }
}

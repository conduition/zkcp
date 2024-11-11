pub trait Program {
    fn id() -> [u32; 8];
    fn elf() -> &'static [u8];
    fn aux_input_len() -> usize;
    fn appendix_len() -> usize;
}

#[repr(transparent)]
#[derive(PartialEq, Eq)]
pub struct Syscall(pub usize);

impl Syscall {
    pub const CapIdentify: Self = Self(1);
    pub const ConWrite: Self = Self(2);
    pub const MemSplit: Self = Self(3);
    pub const TaskMapMem: Self = Self(4);
    pub const TaskUnmapMem: Self = Self(5);
    pub const TaskMapCap: Self = Self(6);
    pub const TaskUnmapCap: Self = Self(7);
}

#[repr(usize)]
#[derive(Debug)]
pub enum SysError {
    InvalidCall = 1,
    InvalidCapType = 2,
    SlotEmpty = 3,
    SlotNotEmpty = 4,
    WrongSize = 5,
    WrongAlign = 6,
    InvalidValue = 7,
}

#[repr(usize)]
#[derive(Debug)]
pub enum Prot {
    Read = 1,
    ReadWrite = 3,
    Execute = 4,
    ReadExecute = 5,
}

impl TryFrom<usize> for Prot {
    type Error = SysError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Prot::Read),
            3 => Ok(Prot::ReadWrite),
            4 => Ok(Prot::Execute),
            5 => Ok(Prot::ReadExecute),
            _ => Err(SysError::InvalidValue),
        }
    }
}

#[repr(transparent)]
struct CapAddr<'a>(usize, core::marker::PhantomData<&'a ()>);


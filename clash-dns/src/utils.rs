use std::io;

pub fn new_io_error<T>(msg: T) -> io::Error
where
    T: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::other(msg.into())
}

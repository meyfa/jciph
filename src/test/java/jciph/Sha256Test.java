package jciph;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import net.meyfa.jciph.hashing.Sha256;


public class Sha256Test
{
    private static class MockSha256 extends Sha256
    {
        private int blocksProcessed = 0;

        // exists so that we can access it here
        @Override
        protected byte[] pad(byte[] message, int length)
        {
            return super.pad(message, length);
        }

        @Override
        protected void processBlock(byte[] block, int off)
        {
            super.processBlock(block, off);
            ++blocksProcessed;
        }
    }

    // hash(byte[])

    @Test
    public void testHashEmpty()
    {
        byte[] b = {};
        byte[] expected = DatatypeConverter.parseHexBinary(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        assertArrayEquals(expected, new Sha256().hash(b));
    }

    @Test
    public void testHashRegular()
    {
        byte[] b = "Hello world!".getBytes(StandardCharsets.US_ASCII);
        byte[] expected = DatatypeConverter.parseHexBinary(
                "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a");

        assertArrayEquals(expected, new Sha256().hash(b));
    }

    @Test
    public void testHashLong()
    {
        byte[] b = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
                + "Proin pulvinar turpis purus, sit amet dapibus magna commodo "
                + "quis metus.").getBytes(StandardCharsets.US_ASCII);
        byte[] expected = DatatypeConverter.parseHexBinary(
                "60497604d2f6b4df42cea5efb8956f587f81a4ad66fa1b65d9e085224d255036");

        assertArrayEquals(expected, new Sha256().hash(b));
    }

    @Test
    public void testHashRawBytes()
    {
        byte[] b = new byte[256];
        for (int i = 0; i < b.length; ++i) {
            b[i] = (byte) i;
        }

        byte[] expected = DatatypeConverter.parseHexBinary(
                "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880");

        assertArrayEquals(expected, new Sha256().hash(b));
    }

    // finish()

    @Test
    public void testFinishCallsProcessBlockTwiceIfNeeded()
    {
        MockSha256 mock = new MockSha256();
        mock.hash(new byte[55]);

        assertEquals(2, mock.blocksProcessed);
    }

    // protected pad(byte[], int)

    @Test
    public void testPaddedLengthDivisibleByBlockSize()
    {
        byte[] b = { 0, 1, 2, 3, 0 };

        byte[] padded = new MockSha256().pad(b, b.length);

        assertTrue(padded.length % 64 == 0);
    }

    @Test
    public void testPaddedMessageHas1Bit()
    {
        byte[] b = new byte[64];

        byte[] padded = new MockSha256().pad(b, b.length);

        assertEquals((byte) 0b1000_0000, padded[b.length]);
    }

    @Test
    public void testPaddingAllZero()
    {
        byte[] b = { 1, 1, 1, 1, 1, 1, 1, };

        byte[] padded = new MockSha256().pad(b, b.length);

        for (int i = b.length + 1; i < padded.length - 8; ++i) {
            assertEquals("byte " + i + " not 0", 0, padded[i]);
        }
    }

    @Test
    public void testPaddingHasTotalSize()
    {
        MockSha256 mock = new MockSha256();
        mock.digest(new byte[64]);
        mock.digest(new byte[64]);
        mock.digest(new byte[32]);

        ByteBuffer buf = ByteBuffer.wrap(mock.pad(new byte[0], 0));
        buf.position(buf.capacity() - 8);

        assertEquals((64 + 64) * Byte.SIZE, buf.getLong());
    }
}

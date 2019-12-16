package org.tamrielrebuilt.bsa;

import java.io.Closeable;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BsaHashChecker implements Closeable {
	public static void main(String[] args) {
		if(args.length == 0) {
			System.out.println("Usage: [path to BSA] [optional additional BSAs]");
			System.exit(0);
		}
		Map<Long, List<String>> count = new HashMap<>();
		for(String path : args) {
			try(BsaHashChecker checker = new BsaHashChecker(new File(path))) {
				checker.checkHashes(count);
			} catch(Exception e) {
				e.printStackTrace();
				System.exit(1);
			}
		}
		count.values().stream().filter(v -> v.size() > 1).forEach(System.out::println);
	}

	private final RandomAccessFile file;
	private int hashOffset;
	private int files;

	public BsaHashChecker(File file) throws FileNotFoundException {
		this.file = new RandomAccessFile(file, "r");
	}

	public void checkHashes(Map<Long, List<String>> count) throws IOException {
		readHeader();
		skip(files * 8);
		int[] offsets = readFileNameOffsets();
		String[] names = readFileNames(offsets);
		countHashes(names, count);
	}

	private void readHeader() throws IOException {
		int version = readInt();
		if(version != 256) {
			throw new IOException("Invalid BSA version: " + version);
		}
		hashOffset = readInt();
		files = readInt();
	}

	private int[] readFileNameOffsets() throws IOException {
		int[] offsets = new int[files];
		for(int i = 0; i < files; i++) {
			offsets[i] = readInt();
		}
		return offsets;
	}

	private String[] readFileNames(int[] offsets) throws IOException {
		String[] names = new String[offsets.length];
		byte[] buffer = new byte[54];
		for(int i = 0; i < names.length; i++) {
			int length;
			if(i < names.length - 1) {
				length = offsets[i + 1];
			} else {
				length = hashOffset - files * 12;
			}
			length -= offsets[i];
			if(length > buffer.length) {
				buffer = new byte[length];
			}
			int read = file.read(buffer, 0, length);
			if(read < length) {
				throw new IOException("Failed to read file name");
			}
			names[i] = new String(buffer, 0, length - 1, StandardCharsets.ISO_8859_1);
		}
		return names;
	}

	private void countHashes(String[] names, Map<Long, List<String>> count) throws IOException {
		file.seek(12 + hashOffset);
		for(int i = 0; i < files; i++) {
			long a = readInt() & 0xFFFFFFFFl;
			long b = readInt() & 0xFFFFFFFFl;
			long hash = (a << 32l) | b;
			List<String> list = count.get(hash);
			if(list == null) {
				list = new ArrayList<>(1);
				count.put(hash, list);
			}
			list.add(names[i]);
		}
	}

	private int readInt() throws IOException {
		int out = 0;
		out |= file.read();
		out |= file.read() << 8;
		out |= file.read() << 16;
		out |= file.read() << 24;
		return out;
	}

	private void skip(int bytes) throws IOException {
		while(bytes > 0) {
			int skipped = file.skipBytes(bytes);
			if(skipped <= 0) {
				throw new IOException("Failed to skip");
			}
			bytes -= skipped;
		}
	}

	@Override
	public void close() throws IOException {
		file.close();
	}
}

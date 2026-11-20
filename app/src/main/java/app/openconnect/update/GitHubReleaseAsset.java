/*
 * Copyright (c) 2026 OConnect contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package app.openconnect.update;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashSet;

final class GitHubReleaseAsset {
	private static final long MAX_APK_BYTES = 128L * 1024 * 1024;
	final String version;
	final String url;
	final long size;
	final String digest;

	GitHubReleaseAsset(String version, String url, long size, String digest) {
		this.version = version;
		this.url = url;
		this.size = size;
		this.digest = digest;
	}

	static boolean isSupported(long size, String digest) {
		return size > 0 && size <= MAX_APK_BYTES && digest.matches("sha256:[0-9a-f]{64}");
	}

	File download(Context context) throws Exception {
		File directory = new File(context.getCacheDir(), "updates");
		Files.createDirectories(directory.toPath());
		File apk = new File(directory, "OConnect-Flexible-" + version + ".apk");
		if (apk.isFile() && apk.length() == size) {
			try (InputStream input = Files.newInputStream(apk.toPath())) {
				if (matchesDigest(input, null)) {
					verifyPackage(context, apk);
					return apk;
				}
			}
		}

		File temporary = File.createTempFile("partial-", ".apk", directory);
		try {
			HttpURLConnection connection = openDownload();
			try (InputStream input = connection.getInputStream();
					OutputStream output = Files.newOutputStream(temporary.toPath())) {
				if (!matchesDigest(input, output)) {
					throw new IOException("APK size or SHA-256 differs from the GitHub release asset");
				}
			} finally {
				connection.disconnect();
			}
			verifyPackage(context, temporary);
			Files.move(temporary.toPath(), apk.toPath(), StandardCopyOption.ATOMIC_MOVE);
			return apk;
		} finally {
			Files.deleteIfExists(temporary.toPath());
		}
	}

	private HttpURLConnection openDownload() throws IOException {
		URL endpoint = new URL(url);
		for (int redirects = 0; redirects <= 4; redirects++) {
			String host = endpoint.getHost();
			if (!"https".equals(endpoint.getProtocol()) || !("github.com".equals(host)
					|| "release-assets.githubusercontent.com".equals(host)
					|| "objects.githubusercontent.com".equals(host))) {
				throw new IOException("Unexpected APK download host");
			}
			HttpURLConnection connection = (HttpURLConnection) endpoint.openConnection();
			connection.setInstanceFollowRedirects(false);
			connection.setConnectTimeout(10000);
			connection.setReadTimeout(20000);
			boolean keepOpen = false;
			try {
				int status = connection.getResponseCode();
				if (status == HttpURLConnection.HTTP_OK) {
					keepOpen = true;
					return connection;
				}
				String location = connection.getHeaderField("Location");
				if (status < 300 || status >= 400 || location == null) {
					throw new IOException("APK download returned HTTP " + status);
				}
				endpoint = new URL(endpoint, location);
			} finally {
				if (!keepOpen) {
					connection.disconnect();
				}
			}
		}
		throw new IOException("Too many APK download redirects");
	}

	private boolean matchesDigest(InputStream input, OutputStream copy) throws Exception {
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		byte[] buffer = new byte[32768];
		long total = 0;
		int count;
		while ((count = input.read(buffer)) != -1) {
			total += count;
			if (total > size) {
				return false;
			}
			sha256.update(buffer, 0, count);
			if (copy != null) {
				copy.write(buffer, 0, count);
			}
		}
		StringBuilder actualDigest = new StringBuilder("sha256:");
		for (byte value : sha256.digest()) {
			actualDigest.append(Character.forDigit((value & 0xff) >>> 4, 16));
			actualDigest.append(Character.forDigit(value & 0xf, 16));
		}
		return total == size && digest.contentEquals(actualDigest);
	}

	private void verifyPackage(Context context, File apk) throws Exception {
		PackageManager packages = context.getPackageManager();
		int flags = PackageManager.GET_SIGNING_CERTIFICATES;
		PackageInfo installed = packages.getPackageInfo(context.getPackageName(), flags);
		PackageInfo downloaded = packages.getPackageArchiveInfo(apk.getAbsolutePath(), flags);
		if (downloaded == null || !installed.packageName.equals(downloaded.packageName)
				|| !version.equals(downloaded.versionName)
				|| downloaded.getLongVersionCode() <= installed.getLongVersionCode()) {
			throw new IOException("APK package or version does not match the expected update");
		}
		Signature[] current = installed.signingInfo == null ? null : installed.signingInfo.getApkContentsSigners();
		Signature[] next = downloaded.signingInfo == null ? null : downloaded.signingInfo.getApkContentsSigners();
		if (current == null || current.length == 0 || next == null
				|| !new HashSet<>(Arrays.asList(current)).equals(new HashSet<>(Arrays.asList(next)))) {
			throw new IOException("APK signing certificate differs from the installed app");
		}
	}
}

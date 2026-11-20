/*
 * Copyright (c) 2026 OConnect contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package app.openconnect.update;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.util.Log;
import android.view.View;
import android.widget.ProgressBar;

import androidx.core.content.FileProvider;

import app.openconnect.R;
import app.openconnect.ToolbarActivity;

import java.io.File;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class UpdateDownloadActivity extends ToolbarActivity {

	private static final String TAG = "OConnectUpdate";
	private static final String EXTRA_VERSION = "version";
	private static final String EXTRA_SIZE = "size";
	private static final String EXTRA_DIGEST = "digest";
	private static final String STATE_INSTALL_WHEN_READY = "install_when_ready";
	private static final int REQUEST_INSTALL_PERMISSION = 1;
	private static final ExecutorService DOWNLOADS = Executors.newSingleThreadExecutor();

	private CompletableFuture<?> download;
	private AlertDialog dialog;
	private File verifiedApk;
	private boolean installWhenReady;

	static void start(Activity activity, GitHubReleaseAsset apk) {
		activity.startActivity(new Intent(activity, UpdateDownloadActivity.class)
				.setData(Uri.parse(apk.url))
				.putExtra(EXTRA_VERSION, apk.version)
				.putExtra(EXTRA_SIZE, apk.size)
				.putExtra(EXTRA_DIGEST, apk.digest));
	}

	@Override
	protected void onCreate(Bundle state) {
		super.onCreate(state);
		installWhenReady = state != null && state.getBoolean(STATE_INSTALL_WHEN_READY);

		ProgressBar progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
		progress.setIndeterminate(true);
		int sidePadding = Math.round(24 * getResources().getDisplayMetrics().density);
		progress.setPaddingRelative(sidePadding, 0, sidePadding, 0);
		dialog = new AlertDialog.Builder(this)
				.setTitle(R.string.update_download)
				.setMessage(R.string.update_downloading)
				.setView(progress)
				.setPositiveButton(R.string.update_install, null)
				.setNegativeButton(R.string.update_close, null)
				.create();
		dialog.setOnDismissListener(ignored -> finish());
		dialog.show();
		dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(false);
		dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(view -> requestInstall());

		download = (CompletableFuture<?>) getLastNonConfigurationInstance();
		if (download == null) {
			Intent request = getIntent();
			GitHubReleaseAsset apk = new GitHubReleaseAsset(request.getStringExtra(EXTRA_VERSION),
					request.getDataString(), request.getLongExtra(EXTRA_SIZE, 0),
					request.getStringExtra(EXTRA_DIGEST));
			Context context = getApplicationContext();
			download = CompletableFuture.supplyAsync(() -> {
				try {
					return apk.download(context);
				} catch (Exception error) {
					throw new CompletionException(error);
				}
			}, DOWNLOADS);
		}
		download.whenCompleteAsync((file, error) -> {
			if (isFinishing() || isDestroyed()) {
				return;
			}
			progress.setVisibility(View.GONE);
			if (error != null) {
				Log.w(TAG, "Download or APK verification failed", error);
				dialog.setMessage(getString(R.string.update_download_failed));
				return;
			}
			verifiedApk = (File) file;
			dialog.setMessage(getString(R.string.update_ready_to_install));
			dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(true);
			if (installWhenReady) {
				openInstaller();
			}
		}, getMainExecutor());
	}

	@Override
	public Object onRetainNonConfigurationInstance() {
		return download;
	}

	@Override
	protected void onSaveInstanceState(Bundle outState) {
		outState.putBoolean(STATE_INSTALL_WHEN_READY, installWhenReady);
		super.onSaveInstanceState(outState);
	}

	@Override
	protected void onDestroy() {
		dialog.setOnDismissListener(null);
		dialog.dismiss();
		super.onDestroy();
	}

	private void requestInstall() {
		if (getPackageManager().canRequestPackageInstalls()) {
			openInstaller();
			return;
		}
		try {
			startActivityForResult(new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
					Uri.fromParts("package", getPackageName(), null)), REQUEST_INSTALL_PERMISSION);
		} catch (ActivityNotFoundException | SecurityException error) {
			showInstallerError(error);
		}
	}

	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data) {
		super.onActivityResult(requestCode, resultCode, data);
		if (requestCode == REQUEST_INSTALL_PERMISSION) {
			if (getPackageManager().canRequestPackageInstalls()) {
				installWhenReady = true;
				if (verifiedApk != null) {
					openInstaller();
				}
			} else {
				dialog.setMessage(getString(R.string.update_install_permission_required));
			}
		}
	}

	private void openInstaller() {
		installWhenReady = false;
		if (!verifiedApk.isFile()) {
			dialog.setMessage(getString(R.string.update_download_failed));
			return;
		}
		try {
			Uri apkUri = FileProvider.getUriForFile(this, getPackageName() + ".updates", verifiedApk);
			startActivity(new Intent(Intent.ACTION_VIEW)
					.setDataAndType(apkUri, "application/vnd.android.package-archive")
					.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION));
		} catch (ActivityNotFoundException | SecurityException error) {
			showInstallerError(error);
		}
	}

	private void showInstallerError(Exception error) {
		Log.w(TAG, "Android package installer is unavailable", error);
		dialog.setMessage(getString(R.string.update_installer_unavailable));
	}
}

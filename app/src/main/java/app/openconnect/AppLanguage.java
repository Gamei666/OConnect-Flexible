// SPDX-License-Identifier: GPL-2.0-or-later
package app.openconnect;

import android.app.LocaleManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.os.Build;
import android.os.LocaleList;
import android.preference.PreferenceManager;

public final class AppLanguage {
    public static final String PREFERENCE = "app_language";

    private AppLanguage() {}

    public static String selectedTag(Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return context.getSystemService(LocaleManager.class).getApplicationLocales().toLanguageTags();
        }
        return preferences(context).getString(PREFERENCE, "");
    }

    public static void select(Context context, String tag) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.getSystemService(LocaleManager.class).setApplicationLocales(LocaleList.forLanguageTags(tag));
        } else {
            preferences(context).edit().putString(PREFERENCE, tag).apply();
        }
    }

    public static Context localize(Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return context;
        }
        return localizeLegacy(context, selectedTag(context));
    }

    static Context localizeLegacy(Context context, String tag) {
        if (tag.isEmpty()) {
            return context;
        }
        Configuration override = new Configuration();
        override.setLocales(LocaleList.forLanguageTags(tag));
        return context.createConfigurationContext(override);
    }

    static void migrate(Context context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return;
        SharedPreferences preferences = preferences(context);
        if (!preferences.contains(PREFERENCE)) return;
        String legacyTag = preferences.getString(PREFERENCE, "");
        if (selectedTag(context).isEmpty() && !legacyTag.isEmpty()) {
            select(context, legacyTag);
        }
        preferences.edit().remove(PREFERENCE).apply();
    }

    private static SharedPreferences preferences(Context context) {
        return PreferenceManager.getDefaultSharedPreferences(context);
    }
}

/**
 * Copyright (c) 2000-present Liferay, Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 */

package com.liferay.gradle.plugins.workspace;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;

import com.liferay.gradle.plugins.workspace.configurators.ExtProjectConfigurator;
import com.liferay.gradle.plugins.workspace.configurators.ModulesProjectConfigurator;
import com.liferay.gradle.plugins.workspace.configurators.PluginsProjectConfigurator;
import com.liferay.gradle.plugins.workspace.configurators.RootProjectConfigurator;
import com.liferay.gradle.plugins.workspace.configurators.ThemesProjectConfigurator;
import com.liferay.gradle.plugins.workspace.configurators.WarsProjectConfigurator;
import com.liferay.gradle.plugins.workspace.internal.util.GradleUtil;
import com.liferay.gradle.util.Validator;
import com.liferay.portal.tools.bundle.support.commands.DownloadCommand;
import com.liferay.portal.tools.bundle.support.constants.BundleSupportConstants;

import groovy.lang.Closure;
import groovy.lang.MissingPropertyException;

import java.io.File;

import java.net.URL;

import java.nio.file.Files;
import java.nio.file.Path;

import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.gradle.api.GradleException;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.initialization.Settings;
import org.gradle.api.invocation.Gradle;
import org.gradle.api.logging.Logger;

/**
 * @author David Truong
 * @author Andrea Di Giorgi
 * @author Simon Jiang
 */
public class WorkspaceExtension {

	@SuppressWarnings("serial")
	public WorkspaceExtension(Settings settings) {
		_gradle = settings.getGradle();

		_product = _getProperty(settings, "product", (String)null);

		_projectConfigurators.add(new ExtProjectConfigurator(settings));
		_projectConfigurators.add(new ModulesProjectConfigurator(settings));
		_projectConfigurators.add(new PluginsProjectConfigurator(settings));
		_projectConfigurators.add(new ThemesProjectConfigurator(settings));
		_projectConfigurators.add(new WarsProjectConfigurator(settings));

		_appServerTomcatVersion = GradleUtil.getProperty(
			settings, "app.server.tomcat.version",
			_getDefaultAppServerVersion());
		_bundleCacheDir = _getProperty(
			settings, "bundle.cache.dir", _BUNDLE_CACHE_DIR);
		_bundleDistRootDirName = _getProperty(
			settings, "bundle.dist.root.dir", _BUNDLE_DIST_ROOT_DIR_NAME);
		_bundleTokenDownload = _getProperty(
			settings, "bundle.token.download", _BUNDLE_TOKEN_DOWNLOAD);
		_bundleTokenEmailAddress = _getProperty(
			settings, "bundle.token.email.address",
			_BUNDLE_TOKEN_EMAIL_ADDRESS);
		_bundleTokenForce = _getProperty(
			settings, "bundle.token.force", _BUNDLE_TOKEN_FORCE);
		_bundleTokenPassword = _getProperty(
			settings, "bundle.token.password", _BUNDLE_TOKEN_PASSWORD);
		_bundleTokenPasswordFile = _getProperty(
			settings, "bundle.token.password.file",
			_BUNDLE_TOKEN_PASSWORD_FILE);
		_bundleUrl = _getProperty(
			settings, "bundle.url", _getDefaultProductBundleUrl());
		_configsDir = _getProperty(
			settings, "configs.dir",
			BundleSupportConstants.DEFAULT_CONFIGS_DIR_NAME);
		_dockerContainerId = new Closure<Void>(_gradle) {

			@SuppressWarnings("unused")
			public String doCall() {
				Project rootProject = _gradle.getRootProject();

				return rootProject.getName() + "-liferay";
			}

		};
		_dockerDir = _getProperty(settings, "docker.dir", _DOCKER_DIR);
		_dockerImageId = new Closure<Void>(_gradle) {

			@SuppressWarnings("unused")
			public String doCall() {
				Project rootProject = _gradle.getRootProject();

				Object version = rootProject.getVersion();

				if (Objects.equals(version, "unspecified")) {
					String dockerImageLiferay = getDockerImageLiferay();

					int index = dockerImageLiferay.indexOf(":");

					version = dockerImageLiferay.substring(index + 1);
				}
				else {
					version = rootProject.getVersion();
				}

				return String.format(
					"%s-liferay:%s", rootProject.getName(), version);
			}

		};
		_dockerImageLiferay = _getProperty(
			settings, "docker.image.liferay", _getDefaultDockerImage());
		_environment = _getProperty(
			settings, "environment",
			BundleSupportConstants.DEFAULT_ENVIRONMENT);
		_homeDir = _getProperty(
			settings, "home.dir",
			BundleSupportConstants.DEFAULT_LIFERAY_HOME_DIR_NAME);
		_targetPlatformVersion = _getProperty(
			settings, "target.platform.version",
			_getDefaultTargetplatformVersion());

		_rootProjectConfigurator = new RootProjectConfigurator(settings);

		_gradle.afterProject(
			new Closure<Void>(_gradle) {

				@SuppressWarnings("unused")
				public void doCall() {
					Project rootProject = _gradle.getRootProject();

					Logger logger = rootProject.getLogger();

					if (!logger.isLifecycleEnabled()) {
						return;
					}

					if (_product == null) {
						logger.lifecycle(
							"The property `liferay.workspace.product` has " +
								"not been set. It is recommended to set this " +
									"property in gradle.properties in the " +
										"workspace directory. See LPS-111700.");

						return;
					}

					String overridePropertyInfo =
						"The %s property is currently overriding the default " +
							"value managed by the liferay.workspace.product " +
								"setting.";

					if (!Objects.equals(
							getAppServerTomcatVersion(),
							_getDefaultAppServerVersion())) {

						logger.lifecycle(
							String.format(
								overridePropertyInfo,
								"app.server.tomcat.version"));
					}

					if (!Objects.equals(
							getBundleUrl(), _getDefaultProductBundleUrl())) {

						logger.lifecycle(
							String.format(
								overridePropertyInfo,
								"liferay.workspace.bundle.url"));
					}

					if (!Objects.equals(
							getDockerImageLiferay(),
							_getDefaultDockerImage())) {

						logger.lifecycle(
							String.format(
								overridePropertyInfo,
								"liferay.workspace.docker.image.liferay"));
					}

					if (!Objects.equals(
							getTargetPlatformVersion(),
							_getDefaultTargetplatformVersion())) {

						logger.lifecycle(
							String.format(
								overridePropertyInfo,
								"liferay.workspace.target.platform.version"));
					}
				}

			});
	}

	public String getAppServerTomcatVersion() {
		return GradleUtil.toString(_appServerTomcatVersion);
	}

	public File getBundleCacheDir() {
		return GradleUtil.toFile(_gradle.getRootProject(), _bundleCacheDir);
	}

	public String getBundleDistRootDirName() {
		return GradleUtil.toString(_bundleDistRootDirName);
	}

	public String getBundleTokenEmailAddress() {
		return GradleUtil.toString(_bundleTokenEmailAddress);
	}

	public String getBundleTokenPassword() {
		return GradleUtil.toString(_bundleTokenPassword);
	}

	public File getBundleTokenPasswordFile() {
		return GradleUtil.toFile(
			_gradle.getRootProject(), _bundleTokenPasswordFile);
	}

	public String getBundleUrl() {
		return GradleUtil.toString(_bundleUrl);
	}

	public File getConfigsDir() {
		return GradleUtil.toFile(_gradle.getRootProject(), _configsDir);
	}

	public String getDockerContainerId() {
		return GradleUtil.toString(_dockerContainerId);
	}

	public File getDockerDir() {
		return GradleUtil.toFile(_gradle.getRootProject(), _dockerDir);
	}

	public String getDockerImageId() {
		return GradleUtil.toString(_dockerImageId);
	}

	public String getDockerImageLiferay() {
		return GradleUtil.toString(_dockerImageLiferay);
	}

	public String getEnvironment() {
		return GradleUtil.toString(_environment);
	}

	public File getHomeDir() {
		return GradleUtil.toFile(_gradle.getRootProject(), _homeDir);
	}

	public String getProduct() {
		return GradleUtil.toString(_product);
	}

	public Iterable<ProjectConfigurator> getProjectConfigurators() {
		return Collections.unmodifiableSet(_projectConfigurators);
	}

	public Plugin<Project> getRootProjectConfigurator() {
		return _rootProjectConfigurator;
	}

	public String getTargetPlatformVersion() {
		return GradleUtil.toString(_targetPlatformVersion);
	}

	public boolean isBundleTokenDownload() {
		return GradleUtil.toBoolean(_bundleTokenDownload);
	}

	public boolean isBundleTokenForce() {
		return GradleUtil.toBoolean(_bundleTokenForce);
	}

	public ProjectConfigurator propertyMissing(String name) {
		for (ProjectConfigurator projectConfigurator : _projectConfigurators) {
			if (name.equals(projectConfigurator.getName())) {
				return projectConfigurator;
			}
		}

		throw new MissingPropertyException(name, ProjectConfigurator.class);
	}

	public void setBundleCacheDir(Object bundleCacheDir) {
		_bundleCacheDir = bundleCacheDir;
	}

	public void setBundleDistRootDirName(Object bundleDistRootDirName) {
		_bundleDistRootDirName = bundleDistRootDirName;
	}

	public void setBundleTokenDownload(Object bundleTokenDownload) {
		_bundleTokenDownload = bundleTokenDownload;
	}

	public void setBundleTokenEmailAddress(Object bundleTokenEmailAddress) {
		_bundleTokenEmailAddress = bundleTokenEmailAddress;
	}

	public void setBundleTokenForce(Object bundleTokenForce) {
		_bundleTokenForce = bundleTokenForce;
	}

	public void setBundleTokenPassword(Object bundleTokenPassword) {
		_bundleTokenPassword = bundleTokenPassword;
	}

	public void setBundleTokenPasswordFile(Object bundleTokenPasswordFile) {
		_bundleTokenPasswordFile = bundleTokenPasswordFile;
	}

	public void setBundleUrl(Object bundleUrl) {
		_bundleUrl = bundleUrl;
	}

	public void setConfigsDir(Object configsDir) {
		_configsDir = configsDir;
	}

	public void setDockerContainerId(Object dockerContainerId) {
		_dockerContainerId = dockerContainerId;
	}

	public void setDockerDir(Object dockerDir) {
		_dockerDir = dockerDir;
	}

	public void setDockerImageId(Object dockerImageId) {
		_dockerImageId = dockerImageId;
	}

	public void setDockerImageLiferay(Object dockerImageLiferay) {
		_dockerImageLiferay = dockerImageLiferay;
	}

	public void setEnvironment(Object environment) {
		_environment = environment;
	}

	public void setHomeDir(Object homeDir) {
		_homeDir = homeDir;
	}

	public void setProduct(Object product) {
		_product = product;
	}

	public void setTargetPlatformVersion(Object targetPlatformVersion) {
		_targetPlatformVersion = targetPlatformVersion;
	}

	private String _getDefaultAppServerVersion() {
		return Optional.ofNullable(
			_getProductInfo(getProduct())
		).map(
			ProductInfo::getAppServerTomcatVersion
		).orElse(
			null
		);
	}

	private String _getDefaultDockerImage() {
		return Optional.ofNullable(
			_getProductInfo(getProduct())
		).map(
			ProductInfo::getLiferayDockerImage
		).orElse(
			_DOCKER_IMAGE_LIFERAY
		);
	}

	private String _getDefaultProductBundleUrl() {
		return Optional.ofNullable(
			_getProductInfo(getProduct())
		).map(
			ProductInfo::getBundleUrl
		).map(
			url -> {
				Base64.Decoder decoder = Base64.getDecoder();

				return new String(decoder.decode(url));
			}
		).orElse(
			BundleSupportConstants.DEFAULT_BUNDLE_URL
		);
	}

	private String _getDefaultTargetplatformVersion() {
		return Optional.ofNullable(
			_getProductInfo(getProduct())
		).map(
			ProductInfo::getTargetPlatformVersion
		).orElse(
			null
		);
	}

	private ProductInfo _getProductInfo(String product) {
		if (product == null) {
			return null;
		}

		return _productInfos.computeIfAbsent(
			product,
			key -> {
				try {
					DownloadCommand downloadCommand = new DownloadCommand();

					downloadCommand.setCacheDir(_workspaceCacheDir);
					downloadCommand.setPassword(null);
					downloadCommand.setToken(false);
					downloadCommand.setUrl(new URL(_PRODUCT_INFO_URL));
					downloadCommand.setUserName(null);

					downloadCommand.execute();

					Path downloadPath = downloadCommand.getDownloadPath();

					try (JsonReader jsonReader = new JsonReader(
							Files.newBufferedReader(downloadPath))) {

						Gson gson = new Gson();

						TypeToken<Map<String, ProductInfo>> typeToken =
							new TypeToken<Map<String, ProductInfo>>() {
							};

						Map<String, ProductInfo> productInfos = gson.fromJson(
							jsonReader, typeToken.getType());

						return productInfos.get(product);
					}
				}
				catch (Exception exception) {
					throw new GradleException(
						"Unable to get product info for :" + product,
						exception);
				}
			});
	}

	private boolean _getProperty(
		Object object, String keySuffix, boolean defaultValue) {

		return GradleUtil.getProperty(
			object, WorkspacePlugin.PROPERTY_PREFIX + keySuffix, defaultValue);
	}

	private Object _getProperty(
		Object object, String keySuffix, File defaultValue) {

		Object value = GradleUtil.getProperty(
			object, WorkspacePlugin.PROPERTY_PREFIX + keySuffix);

		if ((value instanceof String) && Validator.isNull((String)value)) {
			value = null;
		}

		if (value == null) {
			return defaultValue;
		}

		return value;
	}

	private String _getProperty(
		Object object, String keySuffix, String defaultValue) {

		return GradleUtil.getProperty(
			object, WorkspacePlugin.PROPERTY_PREFIX + keySuffix, defaultValue);
	}

	private static final File _BUNDLE_CACHE_DIR = new File(
		System.getProperty("user.home"),
		BundleSupportConstants.DEFAULT_BUNDLE_CACHE_DIR_NAME);

	private static final String _BUNDLE_DIST_ROOT_DIR_NAME = null;

	private static final boolean _BUNDLE_TOKEN_DOWNLOAD = false;

	private static final String _BUNDLE_TOKEN_EMAIL_ADDRESS = null;

	private static final boolean _BUNDLE_TOKEN_FORCE = false;

	private static final String _BUNDLE_TOKEN_PASSWORD = null;

	private static final String _BUNDLE_TOKEN_PASSWORD_FILE = null;

	private static final String _DEFAULT_WORKSPACE_CACHE_DIR_NAME =
		".liferay/workspace";

	private static final File _DOCKER_DIR = new File(
		Project.DEFAULT_BUILD_DIR_NAME + File.separator + "docker");

	private static final String _DOCKER_IMAGE_LIFERAY =
		"liferay/portal:7.2.0-ga1";

	private static final String _PRODUCT_INFO_URL =
		"https://releases.liferay.com/tools/workspace/.product_info.json";

	private final Object _appServerTomcatVersion;
	private Object _bundleCacheDir;
	private Object _bundleDistRootDirName;
	private Object _bundleTokenDownload;
	private Object _bundleTokenEmailAddress;
	private Object _bundleTokenForce;
	private Object _bundleTokenPassword;
	private Object _bundleTokenPasswordFile;
	private Object _bundleUrl;
	private Object _configsDir;
	private Object _dockerContainerId;
	private Object _dockerDir;
	private Object _dockerImageId;
	private Object _dockerImageLiferay;
	private Object _environment;
	private final Gradle _gradle;
	private Object _homeDir;
	private Object _product;
	private final Map<String, ProductInfo> _productInfos = new HashMap<>();
	private final Set<ProjectConfigurator> _projectConfigurators =
		new HashSet<>();
	private final Plugin<Project> _rootProjectConfigurator;
	private Object _targetPlatformVersion;
	private File _workspaceCacheDir = new File(
		System.getProperty("user.home"), _DEFAULT_WORKSPACE_CACHE_DIR_NAME);

	@SuppressWarnings("unused")
	private class ProductInfo {

		public String getAppServerTomcatVersion() {
			return _appServerTomcatVersion;
		}

		public String getBundleUrl() {
			return _bundleUrl;
		}

		public String getLiferayDockerImage() {
			return _liferayDockerImage;
		}

		public String getLiferayProductVersion() {
			return _liferayProductVersion;
		}

		public String getReleaseDate() {
			return _releaseDate;
		}

		public String getTargetPlatformVersion() {
			return _targetPlatformVersion;
		}

		@SerializedName("appServerTomcatVersion")
		private String _appServerTomcatVersion;

		@SerializedName("bundleUrl")
		private String _bundleUrl;

		@SerializedName("liferayDockerImage")
		private String _liferayDockerImage;

		@SerializedName("liferayProductVersion")
		private String _liferayProductVersion;

		@SerializedName("releaseDate")
		private String _releaseDate;

		@SerializedName("targetPlatformVersion")
		private String _targetPlatformVersion;

	}

}
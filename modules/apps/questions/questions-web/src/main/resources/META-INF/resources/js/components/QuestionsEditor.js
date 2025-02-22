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

import {Editor} from 'frontend-editor-ckeditor-web';
import {useEventListener} from 'frontend-js-react-web';
import {isPhone, isTablet} from 'frontend-js-web';
import React, {useContext, useEffect, useMemo, useRef, useState} from 'react';

import {AppContext} from '../AppContext.es';

const getToolbarSet = (toolbarSet) => {
	if (isPhone()) {
		toolbarSet = 'phone';
	}
	else if (isTablet()) {
		toolbarSet = 'tablet';
	}

	return toolbarSet;
};

export function getCKEditorConfig() {
	const config = {
		allowedContent: true,
		codeSnippet_theme: 'monokai_sublime',
		extraPlugins: 'codesnippet,itemselector',
		height: 216,
		removePlugins: 'elementspath',
	};

	config.toolbar = [
		['Bold', 'Italic', 'Underline', 'Strike'],
		['NumberedList', 'BulletedList'],
		['Outdent', 'Indent'],
		['Blockquote'],
		['CodeSnippet', 'ImageSelector'],
		['Link', 'Unlink'],
		['Undo', 'Redo'],
		['Source'],
	];

	return config;
}

const QuestionsEditor = ({
	contents = '',
	cssClass,
	editorConfig = {},
	initialToolbarSet,
	...props
}) => {
	const editorRef = useRef();

	const context = useContext(AppContext);

	const [toolbarSet, setToolbarSet] = useState(initialToolbarSet);

	const config = useMemo(
		() => ({
			toolbar: toolbarSet,
			...getCKEditorConfig(),
			...editorConfig,
		}),
		[editorConfig, toolbarSet]
	);

	useEffect(() => {
		setToolbarSet(getToolbarSet(initialToolbarSet));
	}, [initialToolbarSet]);

	useEventListener(
		'resize',
		() => setToolbarSet(getToolbarSet(initialToolbarSet)),
		true,
		window
	);

	return (
		<div className={cssClass} id={`${name}Container`}>
			<Editor
				className="lfr-editable"
				config={config}
				data={contents}
				key={toolbarSet}
				onBeforeLoad={(CKEDITOR) => {
					if (CKEDITOR) {
						CKEDITOR.disableAutoInline = true;
						CKEDITOR.getNextZIndex = () => 1000;
						CKEDITOR.dtd.$removeEmpty.i = 0;
						CKEDITOR.dtd.$removeEmpty.span = 0;

						CKEDITOR.on('instanceCreated', ({editor}) => {
							editor.name = name;

							if (context.imageBrowseURL) {
								editor.config.filebrowserImageBrowseUrl = context.imageBrowseURL.replace(
									'EDITOR_NAME_',
									name
								);
							}
						});
					}
				}}
				ref={editorRef}
				{...props}
			/>
		</div>
	);
};

export default QuestionsEditor;

<%--
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
--%>

<%@ include file="/collaborators/init.jsp" %>

<liferay-util:html-top
	outputKey="collaborators_css"
>
	<link href='<%= PortalUtil.getStaticResourceURL(request, application.getContextPath() + "/collaborators/css/main.css") %>' rel="stylesheet" type="text/css" />
</liferay-util:html-top>

<div class="collaborators" id="<portlet:namespace/>collaborators-root">
	<react:component
		data='<%= (Map<String, Object>)request.getAttribute("liferay-sharing:collaborators:data") %>'
		module="collaborators/js/index.es"
	/>
</div>
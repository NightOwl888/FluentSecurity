using System;
using System.ComponentModel;
using System.Web;
using System.Web.Mvc;
using System.Web.Routing;
using FluentSecurity.ServiceLocation;

namespace FluentSecurity
{
	[AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = true)]
	public class HandleSecurityAttribute : AuthorizeAttribute, IAuthorizationFilter
	{
		internal ActionResult OverrideResult { get; private set; }
		internal string ControllerName { get; private set; }
		internal ISecurityHandler Handler { get; private set; }

		public HandleSecurityAttribute() : this(ServiceLocator.Current.Resolve<ISecurityHandler>()) {}

		public HandleSecurityAttribute(ISecurityHandler securityHandler)
		{
			Handler = securityHandler;
		}

		protected override bool AuthorizeCore(HttpContextBase httpContext)
		{
			if (httpContext == null)
			{
				throw new ArgumentNullException("httpContext");
			}

			var routeData = RouteTable.Routes.GetRouteData(httpContext);
			var actionName = routeData.GetRequiredString("action");

			var securityContext = SecurityContext.Current;
			securityContext.Data.RouteValues = routeData.Values;

			OverrideResult = Handler.HandleSecurityFor(ControllerName, actionName, securityContext);

			return (OverrideResult == null);
		}

		public override void OnAuthorization(AuthorizationContext filterContext)
		{
			if (filterContext == null)
			{
				throw new ArgumentNullException("filterContext");
			}

			ControllerName = filterContext.ActionDescriptor.ControllerDescriptor.ControllerType.FullName;

			if (AuthorizeCore(filterContext.HttpContext))
			{
				// ** IMPORTANT **
				// Since we're performing authorization at the action level, the authorization code runs
				// after the output caching module. In the worst case this could allow an authorized user
				// to cause the page to be cached, then an unauthorized user would later be served the
				// cached page. We work around this by telling proxies not to cache the sensitive page,
				// then we hook our custom authorization code into the caching mechanism so that we have
				// the final say on whether a page should be served from the cache.

				var cachePolicy = filterContext.HttpContext.Response.Cache;
				cachePolicy.SetProxyMaxAge(new TimeSpan(0));
				cachePolicy.AddValidationCallback(CacheValidateHandler, null /* data */);
			}
			else
			{
				HandleUnauthorizedRequest(filterContext);
			}
		}

		protected override void HandleUnauthorizedRequest(AuthorizationContext filterContext)
		{
			filterContext.Result = OverrideResult;
		}

		private void CacheValidateHandler(HttpContext context, object data, ref HttpValidationStatus validationStatus)
		{
			validationStatus = OnCacheAuthorization(new HttpContextWrapper(context));
		}

		[Obsolete("Not applicable in this class.")]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		[Browsable(false), EditorBrowsable(EditorBrowsableState.Never)]
		new public string Roles { get; set; }

		[Obsolete("Not applicable in this class.")]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		[Browsable(false), EditorBrowsable(EditorBrowsableState.Never)]
		new public string Users { get; set; }

		[Obsolete("Not applicable in this class.")]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		[Browsable(false), EditorBrowsable(EditorBrowsableState.Never)]
		new public int Order { get; set; }
	}
}
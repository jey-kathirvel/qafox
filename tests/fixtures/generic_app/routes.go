package genericfixture

func registerRoutes(router Router) {
    router.GET("/widgets/:widget_id", showWidget)
    router.POST("/widgets", createWidget)
}

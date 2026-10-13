import { MotionConfig } from 'motion/react';
import { HashRouter, Route, Routes } from 'react-router-dom';
import { AppLayout } from './layouts/AppLayout';
import { Category } from './pages/Category';
import { Home } from './pages/Home';
import { NotFound } from './pages/NotFound';
import { SimPage } from './pages/SimPage';

/** HashRouter: funciona em hospedagem estática (GitHub Pages) mesmo ao recarregar qualquer página. */
export function AppRoutes() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route index element={<Home />} />
        <Route path="categoria/:id" element={<Category />} />
        <Route path="sim/:id" element={<SimPage />} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}

export default function App() {
  return (
    // reducedMotion="user": respeita a preferência do sistema por movimento reduzido.
    <MotionConfig reducedMotion="user">
      <HashRouter>
        <AppRoutes />
      </HashRouter>
    </MotionConfig>
  );
}
